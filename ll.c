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

