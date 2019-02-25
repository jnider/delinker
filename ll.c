#include "ll.h"

linked_list* ll_init(void)
{
   linked_list* ll = malloc(sizeof(struct linked_list));
   if (ll)
   {
      ll->count = 0;
      ll->head = NULL;
   }
   return ll;
}

unsigned int ll_size(const linked_list* ll)
{
   return ll->count;
}

void ll_add(linked_list* ll, void* val)
{
   // create the new node
   list_node* n = malloc(sizeof(list_node));
   n->val = val;
   n->next = NULL;

   // now insert it
   if (!(ll->head))
      ll->head = n;
   else
   {
      list_node* tmp = ll->head;
      while (tmp->next)
         tmp = tmp->next;
      tmp->next = n;
   }
   ll->count++;
}

void* ll_remove(linked_list* ll, const void* data, ll_cmpfunc cmp)
{
	void* val;

   if (!(ll->head))
		return NULL;

	// are we deleting the head node?
	list_node* tmp = ll->head;
	if (cmp(tmp->val, data) == 0)
	{
		ll->head = ll->head->next;
		ll->count--;
		val = tmp->val;
		free(tmp);
		return val;
	}

	// check the rest of the list
	while (tmp->next)
	{
		list_node* del = tmp->next;
		if (cmp(del->val, data) == 0)
		{
			tmp->next = del->next;
			ll->count--;
			val = del->val;
			free(del);
			return val;
		}
		tmp = tmp->next;
	}

	return NULL;
}

void* ll_pop(linked_list* ll)
{
	if (!ll || !ll->head)
		return NULL;

	list_node* tmp = ll->head;
	ll->head = ll->head->next;
	ll->count--;

	return tmp->val;
}

const list_node* ll_iter_start(const linked_list* ll)
{
   return ll->head;
}

void ll_insert(linked_list* ll, list_node* here, void* val)
{
	if (!here)
		return;

   // create the new node
   list_node* n = malloc(sizeof(list_node));
   n->val = val;
   n->next = here->next;
	here->next = n;
   ll->count++;
}

void ll_push(linked_list* ll, void* val)
{
	if (!ll)
		return;

   // create the new node
   list_node* n = malloc(sizeof(list_node));
   n->val = val;
	if (ll->head)
   	n->next = ll->head;
	else
		n->next = NULL;
	ll->head = n;
   ll->count++;
}
