/*
 *
 * SYNwall - Helpers library
 * Copyright (C) 2019 Sorint.lab
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include <linux/module.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)

#include "SYNhelpers.h"

// Implementation for find_module, removed from kernel 5.12
struct module *find_module(const char *name)
{
  struct module *list_modules = NULL;

  /* Try to find the module browsing the list */
  list_for_each_entry(list_modules, THIS_MODULE->list.prev, list)
    {
      if (strcmp(list_modules->name, name) == 0)
        {
          return list_modules;
        }
    }
  return NULL;
}

#endif
