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

void* ll_pop(linked_list* ll)
{
   list_node* tmp = ll->head;
   if (!ll->head)
   {
      ll->head = ll->head->next;
      ll->count--;
   }
   return tmp;
}

