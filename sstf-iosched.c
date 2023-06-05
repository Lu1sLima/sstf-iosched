/*
 * SSTF IO Scheduler
 *
 * For Kernel 4.13.9
 */

#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>

/* SSTF data structure. */
struct sstf_data {
	struct list_head queue;
};
long long unsigned int lastDispatched = 0;

static void print_queue(struct request_queue *q, struct request *rq);
static long long unsigned int calculate_difference(long long unsigned int a, long long unsigned int b);

static void sstf_merged_requests(struct request_queue *q, struct request *rq,
				 struct request *next)
{
	list_del_init(&next->queuelist);
}

/* Esta função despacha o próximo bloco a ser lido. */
static int sstf_dispatch(struct request_queue *q, int force){
	struct sstf_data *nd = q->elevator->elevator_data;
	char direction = 'R';
	struct request *rq;

	// print_queue(q, rq);
	// printk(KERN_EMERG "<---------- [DISPATCH] ---------->");
	// printk(KERN_EMERG "[LAST DISPATCHED] --> %c %llu\n", direction, lastDispatched);

	if (list_empty(&nd->queue)) {
		lastDispatched = 0;
		return 0;
	}


	rq = list_first_entry_or_null(&nd->queue, struct request, queuelist);

	long long unsigned int least = calculate_difference(blk_rq_pos(rq), lastDispatched);
	struct request *dispatched = rq;
	struct request *entry;

	// printk(KERN_EMERG "[LEAST] --> %c %llu\n", direction, least);
	list_for_each_entry(entry, &nd->queue, queuelist) {

		long long unsigned int diff = calculate_difference(blk_rq_pos(entry), lastDispatched);

		if (diff < least) {
			// printk(KERN_EMERG "[DIFF < LEAST] --> %c %llu\n", direction, least);
			// printk(KERN_EMERG "[ENTRY] --> %c %llu\n", direction, blk_rq_pos(entry));
			least = diff;
			dispatched = entry;
		}
	}

	if (dispatched) {
		printk(KERN_EMERG "[DISPATCH] --> %c %llu\n", direction, blk_rq_pos(dispatched));
		list_del_init(&dispatched->queuelist);
		elv_dispatch_sort(q, dispatched);
		lastDispatched = blk_rq_pos(dispatched);
		// printk(KERN_EMERG "[SSTF] dsp %c %llu\n", direction, blk_rq_pos(rq));

		return 1;
	}
	return 0;
}

static long long unsigned int calculate_difference(long long unsigned int a, long long unsigned int b) {
    if (a < b) {
        return b - a;
    } else {
        return a - b;
    }
}

static void sstf_add_request(struct request_queue *q, struct request *rq) {
	struct sstf_data *nd = q->elevator->elevator_data;
	char direction = 'R';
	struct request *req;
	
	printk(KERN_EMERG "[ADD] --> %c %llu\n", direction, blk_rq_pos(rq));

	
	if (list_empty(&nd->queue)) {
		list_add_tail(&rq->queuelist, &nd->queue);
		return;
	}

	struct request *entry;
	int found = 0;
	list_for_each_entry(entry, &nd->queue, queuelist) {
		if (blk_rq_pos(rq) < blk_rq_pos(entry)) {
			list_add_tail(&rq->queuelist, &entry->queuelist);
			found = 1;
			return;
		}
	}

	// Caso o valor seja maior do que todos os valores na lista, adiciona no final
	if (found == 0) {
		list_add_tail(&rq->queuelist, &nd->queue);
	}

	// print_queue(q, rq);
}

static void print_queue(struct request_queue *q, struct request *rq) {
	struct sstf_data *nd = q->elevator->elevator_data;
	struct request *entry;

	printk(KERN_EMERG "========== [LISTA] ==========\n");

	list_for_each_entry(entry, &nd->queue, queuelist) {
		printk(KERN_EMERG "-> %llu\n", blk_rq_pos(entry));
	}
}

static int sstf_init_queue(struct request_queue *q, struct elevator_type *e){
	struct sstf_data *nd;
	struct elevator_queue *eq;

	/* Implementação da inicialização da fila (queue).
	 *
	 * Use como exemplo a inicialização da fila no driver noop-iosched.c
	 *
	 */

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	nd = kmalloc_node(sizeof(*nd), GFP_KERNEL, q->node);
	if (!nd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = nd;

	INIT_LIST_HEAD(&nd->queue);

	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);

	return 0;
}

static void sstf_exit_queue(struct elevator_queue *e)
{
	struct sstf_data *nd = e->elevator_data;

	/* Implementação da finalização da fila (queue).
	 *
	 * Use como exemplo o driver noop-iosched.c
	 *
	 */
	BUG_ON(!list_empty(&nd->queue));
	kfree(nd);
}

/* Infrastrutura dos drivers de IO Scheduling. */
static struct elevator_type elevator_sstf = {
	.ops.sq = {
		.elevator_merge_req_fn		= sstf_merged_requests,
		.elevator_dispatch_fn		= sstf_dispatch,
		.elevator_add_req_fn		= sstf_add_request,
		.elevator_init_fn		= sstf_init_queue,
		.elevator_exit_fn		= sstf_exit_queue,
	},
	.elevator_name = "sstf",
	.elevator_owner = THIS_MODULE,
};

/* Inicialização do driver. */
static int __init sstf_init(void)
{
	return elv_register(&elevator_sstf);
}

/* Finalização do driver. */
static void __exit sstf_exit(void)
{
	elv_unregister(&elevator_sstf);
}

module_init(sstf_init);
module_exit(sstf_exit);

MODULE_AUTHOR("Miguel Xavier");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SSTF IO scheduler");