"""
End-to-End Demo: Order Processing for a Restaurant Management Platform

This test demonstrates two things:

1. The postkit/queue SDK (QueueClient) - the generic job queue API
2. Domain-specific helpers (FoodFlow) - how customers layer their own abstractions

SCENARIO: FoodFlow
==================
FoodFlow builds a multi-tenant restaurant management platform (like PetPooja).
Each restaurant is a tenant. They need background job processing for:

- Order routing to kitchen displays (dine-in prioritized over delivery)
- Delivery dispatch to rider partners
- Billing (receipt generation after order completion)

postkit/queue handles the job lifecycle. FoodFlow's code handles the business
logic (cooking, dispatching, PDF rendering).
"""

from datetime import timedelta

from postkit.queue import QueueClient

# Domain-specific helpers - how customers wrap the generic SDK with their
# own domain language. The SDK deals in queues and jobs; this layer deals
# in orders, deliveries, and invoices.


class FoodFlow:
    """
    FoodFlow's domain-specific order processing helpers.

    Built on top of QueueClient, this provides restaurant-specific operations
    that compose multiple SDK calls into single business actions. Every
    company would build their own version of this.
    """

    def __init__(self, queue: QueueClient):
        self.queue = queue

    def place_order(self, order_id, items, *, order_type="dine_in", table=None):
        """Place an order: route to kitchen and dispatch delivery if needed.

        Composes one or two pushes into a single business operation. Dine-in
        orders get priority 10 (appear on kitchen display first), delivery
        orders get priority 5 (prepared after dine-in during rush hour).

        For delivery orders, a dispatch job is also created so the rider
        assignment service can pick it up independently.
        """
        priority = 10 if order_type == "dine_in" else 5
        payload = {"order_id": order_id, "items": items, "type": order_type}
        if table:
            payload["table"] = table

        order_job = self.queue.push(
            "orders",
            payload,
            priority=priority,
            tags=[order_type],
            metadata={"order_id": order_id},
            unique_key=order_id,
        )

        delivery_job = None
        if order_type == "delivery":
            delivery_job = self.queue.push(
                "delivery",
                {"order_id": order_id, "status": "awaiting_pickup"},
                tags=["delivery"],
            )

        return {"order_job": order_job, "delivery_job": delivery_job}

    def complete_order(self, job_id, fence, order_id, amount):
        """Complete an order: acknowledge it and push a billing job.

        Composes an ack and a push into a single business operation.
        The ack removes the order from the kitchen display, and the billing
        job triggers receipt/invoice generation.
        """
        self.queue.ack(job_id, fence)

        billing_job = self.queue.push(
            "billing",
            {
                "order_id": order_id,
                "amount": amount,
                "currency": "INR",
                "type": "receipt",
            },
        )

        return billing_job


class TestOrderProcessing:
    """
    FoodFlow's restaurant platform uses postkit/queue to process orders
    from placement through completion.
    """

    def test_order_processing(self, queue: QueueClient):
        """
        Full order lifecycle from placement to billing, demonstrating how
        application code interacts with postkit/queue.
        """
        app = FoodFlow(queue)

        # 1. Place orders
        # Dinner rush at a Mumbai restaurant. A delivery order comes in
        # first, then a dine-in order for table T-3.
        delivery = app.place_order(
            "ORD-101", ["biryani", "raita"], order_type="delivery"
        )
        dinein = app.place_order(
            "ORD-102", ["thali", "lassi"], order_type="dine_in", table="T-3"
        )

        # Delivery order created both a kitchen job and a dispatch job.
        # Dine-in only needs the kitchen job.
        assert delivery["order_job"] is not None
        assert delivery["delivery_job"] is not None
        assert dinein["delivery_job"] is None

        # 2. Priority routing
        # Kitchen display pulls the next order. Dine-in (priority 10)
        # comes before delivery (priority 5), even though delivery was
        # placed first. Priority ordering with zero application logic.
        first = queue.pull("orders", worker_id="kitchen-display-1")
        assert first["payload"]["order_id"] == "ORD-102"
        assert first["payload"]["table"] == "T-3"

        # 3. Complete and invoice
        # Chef finishes the thali. complete_order acks it and creates
        # a billing job for receipt generation.
        billing_id = app.complete_order(
            first["id"], first["fence_token"], "ORD-102", 450
        )

        billing = queue.pull("billing", worker_id="pdf-worker-1")
        assert billing["id"] == billing_id
        assert billing["payload"]["amount"] == 450
        queue.ack(billing["id"], billing["fence_token"])

        # 4. Transient failure
        # Kitchen display tablet goes offline while showing the biryani
        # order. Nack returns it to the queue for another worker.
        second = queue.pull("orders", worker_id="kitchen-display-1")
        assert second["payload"]["order_id"] == "ORD-101"

        returned = queue.nack(
            second["id"], second["fence_token"], error="display offline"
        )
        assert returned is True  # Job returned to queue, not moved to DLQ.

        # 5. Permanent failure
        # A new order references an item the kitchen can't make tonight.
        # Fail moves it to the dead letter queue.
        app.place_order("ORD-103", ["pav bhaji"], order_type="dine_in", table="T-5")
        bad_order = queue.pull("orders", worker_id="kitchen-display-2")

        assert queue.fail(
            bad_order["id"],
            bad_order["fence_token"],
            error="pav bhaji unavailable tonight",
        )

        # 6. Batch dispatch
        # Evening rush: multiple delivery orders are ready for riders.
        # The delivery queue already has ORD-101's dispatch job from step 1.
        for i in range(3):
            queue.push(
                "delivery",
                {"order_id": f"ORD-20{i}", "address": f"Addr-{i}"},
                tags=["delivery"],
            )

        # Dispatch service pulls all available jobs at once.
        riders = queue.pull_batch("delivery", 10, worker_id="dispatch-svc")
        assert len(riders) == 4  # 1 from step 1 + 3 new.

        dispatched = queue.ack_batch(
            [(job["id"], job["fence_token"]) for job in riders]
        )
        assert dispatched == 4

        # 7. Deduplication
        # Customer's app glitches and submits the same order twice.
        # unique_key (set in place_order) prevents duplicates.
        first_submit = app.place_order(
            "ORD-200", ["dosa"], order_type="dine_in", table="T-1"
        )
        duplicate = app.place_order(
            "ORD-200", ["dosa"], order_type="dine_in", table="T-1"
        )

        assert first_submit["order_job"] is not None
        assert duplicate["order_job"] is None  # Deduplicated.

    def test_operations(self, queue: QueueClient):
        """
        Operational tooling: monitoring, failure recovery, and cleanup.
        """
        app = FoodFlow(queue)

        # 1. Queue health
        # Ops dashboard shows per-queue breakdown during dinner service.
        app.place_order("ORD-301", ["paneer tikka"], order_type="dine_in")
        app.place_order("ORD-302", ["chole bhature"], order_type="delivery")
        queue.push("billing", {"order_id": "ORD-300", "amount": 200})

        # Pull and fail one order to populate the dead letter queue.
        job = queue.pull("orders", worker_id="kitchen-display-1")
        assert queue.fail(
            job["id"],
            job["fence_token"],
            error="kitchen closed unexpectedly",
        )

        stats = queue.get_queue_stats()
        by_queue = {s["queue"]: s for s in stats}

        assert by_queue["orders"]["pending"] == 1  # ORD-302 still waiting.
        assert by_queue["orders"]["dead_letters"] == 1  # ORD-301 failed.
        assert by_queue["billing"]["pending"] == 1

        # 2. Crashed worker recovery
        # A kitchen display tablet crashes with a job locked. The visibility
        # timeout expires and the maintenance tick reclaims it.
        stuck = queue.pull("orders", worker_id="kitchen-display-3")
        assert stuck["payload"]["order_id"] == "ORD-302"

        # Simulate the tablet being unresponsive past its timeout.
        queue.cursor.execute(
            "UPDATE queue.jobs "
            "SET visibility_timeout_at = now() - interval '1 second' "
            "WHERE namespace = %s AND id = %s",
            (queue.namespace, stuck["id"]),
        )

        reclaimed = queue.tick_timeouts()
        assert len(reclaimed) == 1
        assert reclaimed[0]["job_id"] == stuck["id"]

        # Another display picks it up. The order wasn't lost.
        recovered = queue.pull("orders", worker_id="kitchen-display-4")
        assert recovered["id"] == stuck["id"]
        queue.ack(recovered["id"], recovered["fence_token"])

        # 3. Graceful shutdown
        # Restaurant closes for the night. Two orders are still being
        # displayed. Release the jobs individually so the morning shift need
        # not wait for the visibility timeout; worker ID is diagnostic only.
        app.place_order("ORD-303", ["samosa"], order_type="dine_in")
        app.place_order("ORD-304", ["pakora"], order_type="dine_in")
        closing_jobs = [
            queue.pull("orders", worker_id="kitchen-display-1"),
            queue.pull("orders", worker_id="kitchen-display-1"),
        ]

        for closing_job in closing_jobs:
            queue.release(closing_job["id"], closing_job["fence_token"])

        # Morning shift pulls them.
        for _ in range(2):
            job = queue.pull("orders", worker_id="kitchen-display-morning")
            assert job is not None
            queue.ack(job["id"], job["fence_token"])

        # 4. Dead letter triage
        # Payment gateway was down overnight. Three delivery orders failed
        # because billing couldn't process them.
        for order_id in ("ORD-401", "ORD-402", "ORD-403"):
            app.place_order(order_id, ["late night biryani"], order_type="delivery")
            job = queue.pull("orders", worker_id="kitchen-display-1")
            queue.fail(
                job["id"],
                job["fence_token"],
                error="payment gateway timeout",
            )

        # Morning ops checks the damage. (ORD-301 from step 1 + 3 new = 4.)
        stats = queue.get_queue_stats(queue="orders")
        assert stats[0]["dead_letters"] == 4

        # Retry one specific dead letter to investigate.
        queue.cursor.execute(
            "SELECT id FROM queue.dead_letters "
            "WHERE namespace = %s AND queue = 'orders' "
            "AND retried_at IS NULL ORDER BY id LIMIT 1",
            (queue.namespace,),
        )
        dl_id = queue.cursor.fetchone()[0]
        new_job_id = queue.retry_dead_letter(dl_id)

        retried = queue.pull("orders", worker_id="kitchen-display-1")
        assert retried["id"] == new_job_id
        queue.ack(retried["id"], retried["fence_token"])

        # Gateway is back. Bulk retry the remaining three.
        results = queue.retry_dead_letters("orders")
        assert len(results) == 3

        for _ in results:
            job = queue.pull("orders", worker_id="kitchen-display-1")
            assert job is not None
            queue.ack(job["id"], job["fence_token"])

        # 5. Cleanup
        # Dead letters accumulate over time. Purge entries older than 30 days
        # that were never retried (retried entries are kept as audit records).
        for order_id in ("ORD-501", "ORD-502", "ORD-503"):
            app.place_order(order_id, ["old order"], order_type="dine_in")
            job = queue.pull("orders", worker_id="kitchen-display-1")
            queue.fail(job["id"], job["fence_token"], error="historic failure")

        # Backdate to simulate month-old failures.
        queue.cursor.execute(
            "UPDATE queue.dead_letters "
            "SET failed_at = now() - interval '60 days' "
            "WHERE namespace = %s AND retried_at IS NULL",
            (queue.namespace,),
        )
        purged_dl = queue.purge_dead_letters(older_than=timedelta(days=30))
        assert purged_dl == 3

        # Purge stale pending orders from a test queue.
        queue.push("staging", {"test": True})
        queue.push("staging", {"test": True})
        purged = queue.purge_queue("staging")
        assert purged == 2

        # 6. Audit trail
        # Manager Priya retries a dead letter for a customer escalation.
        # Actor context tracks who authorized the action and why.
        queue.push("orders", {"order_id": "ORD-500", "items": ["dal makhani"]})
        job = queue.pull("orders", worker_id="kitchen-display-1")
        queue.fail(job["id"], job["fence_token"], error="system error")

        queue.cursor.execute(
            "SELECT id FROM queue.dead_letters "
            "WHERE namespace = %s AND original_job_id = %s",
            (queue.namespace, job["id"]),
        )
        dl_id = queue.cursor.fetchone()[0]

        queue.set_actor(actor_id="manager_priya", reason="customer escalation")
        new_job = queue.retry_dead_letter(dl_id)

        queue.cursor.execute(
            "SELECT actor_id, reason FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, new_job),
        )
        row = queue.cursor.fetchone()
        assert row[0] == "manager_priya"
        assert row[1] == "customer escalation"

        queue.clear_actor()

    def test_multi_tenant_isolation(self, make_queue):
        """Two restaurants on the same platform cannot see each other's orders."""
        mumbai = make_queue("foodflow_mumbai")
        delhi = make_queue("foodflow_delhi")

        # Each restaurant pushes an order.
        mumbai.push("orders", {"order_id": "MUM-001", "items": ["vada pav"]})
        delhi.push("orders", {"order_id": "DEL-001", "items": ["chole bhature"]})

        # Each restaurant only sees its own orders.
        mum_job = mumbai.pull("orders")
        assert mum_job["payload"]["order_id"] == "MUM-001"

        del_job = delhi.pull("orders")
        assert del_job["payload"]["order_id"] == "DEL-001"

        # Stats are scoped per tenant.
        mumbai.ack(mum_job["id"], mum_job["fence_token"])
        assert delhi.fail(
            del_job["id"], del_job["fence_token"], error="kitchen closed"
        )

        mum_stats = mumbai.get_stats()
        del_stats = delhi.get_stats()

        assert mum_stats["pending"] == 0
        assert mum_stats["dead"] == 0
        assert del_stats["pending"] == 0
        assert del_stats["dead"] == 1

        # Delhi's dead letter is invisible to Mumbai.
        mumbai.cursor.execute(
            "SELECT count(*) FROM queue.dead_letters WHERE namespace = %s",
            (mumbai.namespace,),
        )
        assert mumbai.cursor.fetchone()[0] == 0
