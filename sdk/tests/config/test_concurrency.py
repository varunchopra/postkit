import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from postkit.config import ConfigClient, ConfigErrorCode, ConfigValidationError

from tests.helpers import make_namespace


def _wait_for_lock(observer, connection):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        row = observer.execute(
            "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
            (connection.info.backend_pid,),
        ).fetchone()
        if row is not None and row[0] == "Lock":
            return
        time.sleep(0.01)
    pytest.fail("concurrent Config operation did not wait for the fixture lock")


def _hold_absent_key_mutation(connection, namespace, key):
    client = ConfigClient(connection.cursor(), namespace)
    assert client.delete(key) == 0


def _hold_existing_key_mutation(connection, namespace, key, version):
    client = ConfigClient(connection.cursor(), namespace)
    assert client.set_default(key, {"unused": True}) == (version, False)


def test_concurrent_defaults_create_exactly_one(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)

    lock_connection = connect()
    _hold_absent_key_mutation(lock_connection, namespace, "plans/free")
    connections = [connect(), connect()]

    def set_default(connection, value):
        client = ConfigClient(connection.cursor(), namespace)
        result = client.set_default("plans/free", value)
        connection.commit()
        return result

    values = [{"tokens": 5_000}, {"tokens": 10_000}]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(set_default, connection, value)
            for connection, value in zip(connections, values)
        ]
        try:
            for connection in connections:
                _wait_for_lock(db_connection, connection)
        finally:
            lock_connection.commit()
        results = [future.result() for future in futures]

    assert sorted(created for _, created in results) == [False, True]
    assert [version for version, _ in results] == [1, 1]
    winning_value = values[[created for _, created in results].index(True)]
    assert reader.get_value("plans/free") == winning_value
    assert [row["version"] for row in reader.history("plans/free")] == [1]


def test_default_cannot_overwrite_uncommitted_set(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)
    reader.set("plans/free", {"tokens": 1_000})

    writer_connection = connect()
    writer = ConfigClient(writer_connection.cursor(), namespace)
    assert writer.set("plans/free", {"tokens": 10_000}) == 2

    default_connection = connect()

    def set_default():
        client = ConfigClient(default_connection.cursor(), namespace)
        result = client.set_default("plans/free", {"tokens": 5_000})
        default_connection.commit()
        return result

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(set_default)
        try:
            _wait_for_lock(db_connection, default_connection)
        finally:
            writer_connection.commit()
        assert future.result() == (2, False)

    assert reader.get_value("plans/free") == {"tokens": 10_000}
    assert [row["version"] for row in reader.history("plans/free")] == [2, 1]


def test_set_racing_default_preserves_ordinary_write(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)

    lock_connection = connect()
    _hold_absent_key_mutation(lock_connection, namespace, "plans/free")
    set_connection = connect()
    default_connection = connect()

    def write_value():
        client = ConfigClient(set_connection.cursor(), namespace)
        version = client.set("plans/free", {"source": "set"})
        set_connection.commit()
        return version

    def write_default():
        client = ConfigClient(default_connection.cursor(), namespace)
        result = client.set_default("plans/free", {"source": "default"})
        default_connection.commit()
        return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        set_future = executor.submit(write_value)
        default_future = executor.submit(write_default)
        try:
            _wait_for_lock(db_connection, set_connection)
            _wait_for_lock(db_connection, default_connection)
        finally:
            lock_connection.commit()
        set_version = set_future.result()
        default_version, default_created = default_future.result()

    history = reader.history("plans/free")
    assert reader.get_value("plans/free") == {"source": "set"}
    assert set_version == history[0]["version"]
    assert [row["version"] for row in history] in ([1], [2, 1])
    assert sum(row["is_active"] for row in history) == 1
    assert (default_version, default_created) in {(1, False), (1, True)}


def test_concurrent_sets_assign_monotonic_versions(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)
    lock_connection = connect()
    _hold_absent_key_mutation(lock_connection, namespace, "plans/free")
    connections = [connect(), connect()]

    def set_value(connection, value):
        client = ConfigClient(connection.cursor(), namespace)
        version = client.set("plans/free", value)
        connection.commit()
        return version

    values = [{"writer": 1}, {"writer": 2}]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(set_value, connection, value)
            for connection, value in zip(connections, values)
        ]
        try:
            for connection in connections:
                _wait_for_lock(db_connection, connection)
        finally:
            lock_connection.commit()
        versions = [future.result() for future in futures]

    assert sorted(versions) == [1, 2]
    history = reader.history("plans/free")
    assert [row["version"] for row in history] == [2, 1]
    assert sum(row["is_active"] for row in history) == 1
    assert reader.get_value("plans/free") == values[versions.index(2)]


def test_rollback_racing_set_has_a_serial_outcome(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)
    reader.set("plans/free", {"version": 1})
    reader.set("plans/free", {"version": 2})

    lock_connection = connect()
    _hold_existing_key_mutation(lock_connection, namespace, "plans/free", 2)
    set_connection = connect()
    rollback_connection = connect()

    def write_value():
        client = ConfigClient(set_connection.cursor(), namespace)
        result = client.set("plans/free", {"version": 3})
        set_connection.commit()
        return result

    def rollback():
        client = ConfigClient(rollback_connection.cursor(), namespace)
        result = client.rollback("plans/free")
        rollback_connection.commit()
        return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        set_future = executor.submit(write_value)
        rollback_future = executor.submit(rollback)
        try:
            _wait_for_lock(db_connection, set_connection)
            _wait_for_lock(db_connection, rollback_connection)
        finally:
            lock_connection.commit()
        assert set_future.result() == 3
        assert rollback_future.result() in {1, 2}

    history = reader.history("plans/free")
    assert [row["version"] for row in history] == [3, 2, 1]
    assert sum(row["is_active"] for row in history) == 1
    assert reader.get_value("plans/free") in ({"version": 2}, {"version": 3})


def test_activate_racing_delete_version_has_a_serial_outcome(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)
    reader.set("plans/free", {"version": 1})
    reader.set("plans/free", {"version": 2})

    lock_connection = connect()
    _hold_existing_key_mutation(lock_connection, namespace, "plans/free", 2)
    activate_connection = connect()
    delete_connection = connect()

    def activate():
        client = ConfigClient(activate_connection.cursor(), namespace)
        result = client.activate("plans/free", 1)
        activate_connection.commit()
        return result

    def delete_version():
        client = ConfigClient(delete_connection.cursor(), namespace)
        try:
            result = client.delete_version("plans/free", 1)
            delete_connection.commit()
            return result
        except ConfigValidationError as exc:
            delete_connection.rollback()
            assert exc.error_code == ConfigErrorCode.BIZ_DELETE_ACTIVE_VERSION
            return "active"

    with ThreadPoolExecutor(max_workers=2) as executor:
        activate_future = executor.submit(activate)
        delete_future = executor.submit(delete_version)
        try:
            _wait_for_lock(db_connection, activate_connection)
            _wait_for_lock(db_connection, delete_connection)
        finally:
            lock_connection.commit()
        activated = activate_future.result()
        deleted = delete_future.result()

    history = reader.history("plans/free")
    if activated:
        assert deleted == "active"
        assert [row["version"] for row in history] == [2, 1]
        assert reader.get_value("plans/free") == {"version": 1}
    else:
        assert deleted is True
        assert [row["version"] for row in history] == [2]
        assert reader.get_value("plans/free") == {"version": 2}


def test_cleanup_winning_activation_race_preserves_active_version(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)
    reader.set("plans/free", {"version": 1})
    reader.set("plans/free", {"version": 2})

    cleanup_connection = connect()
    cleanup = ConfigClient(cleanup_connection.cursor(), namespace)
    assert cleanup.cleanup_old_versions(keep_versions=0) == 1

    activate_connection = connect()

    def activate():
        client = ConfigClient(activate_connection.cursor(), namespace)
        result = client.activate("plans/free", 1)
        activate_connection.commit()
        return result

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(activate)
        try:
            _wait_for_lock(db_connection, activate_connection)
        finally:
            cleanup_connection.commit()
        assert future.result() is False

    assert reader.get_value("plans/free") == {"version": 2}
    history = reader.history("plans/free")
    assert [row["version"] for row in history] == [2]
    assert history[0]["is_active"] is True


def test_rollback_returns_none_when_cleanup_removes_its_candidate(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)
    reader.set("plans/free", {"version": 1})
    reader.set("plans/free", {"version": 2})

    cleanup_connection = connect()
    cleanup = ConfigClient(cleanup_connection.cursor(), namespace)
    assert cleanup.cleanup_old_versions(keep_versions=0) == 1

    rollback_connection = connect()

    def rollback():
        client = ConfigClient(rollback_connection.cursor(), namespace)
        result = client.rollback("plans/free")
        rollback_connection.commit()
        return result

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(rollback)
        try:
            _wait_for_lock(db_connection, rollback_connection)
        finally:
            cleanup_connection.commit()
        assert future.result() is None

    assert reader.get_value("plans/free") == {"version": 2}
    history = reader.history("plans/free")
    assert [row["version"] for row in history] == [2]
    assert history[0]["is_active"] is True


def test_activation_winning_cleanup_race_preserves_activated_version(
    make_config, connect, db_connection, request
):
    namespace = make_namespace(request)
    reader = make_config(namespace)
    reader.set("plans/free", {"version": 1})
    reader.set("plans/free", {"version": 2})

    activate_connection = connect()
    activate = ConfigClient(activate_connection.cursor(), namespace)
    assert activate.activate("plans/free", 1) is True

    cleanup_connection = connect()

    def cleanup():
        client = ConfigClient(cleanup_connection.cursor(), namespace)
        result = client.cleanup_old_versions(keep_versions=0)
        cleanup_connection.commit()
        return result

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(cleanup)
        try:
            _wait_for_lock(db_connection, cleanup_connection)
        finally:
            activate_connection.commit()
        assert future.result() == 0

    assert reader.get_value("plans/free") == {"version": 1}
    history = reader.history("plans/free")
    assert [row["version"] for row in history] == [2, 1]
    assert [row["version"] for row in history if row["is_active"]] == [1]
