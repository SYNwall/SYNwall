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

#include "SYNhelpers.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)

// Implementation for find_module, removed from kernel 5.12
struct module *find_module(const char *name)
{
  struct module *list_modules = NULL;

  // Try to find the module browsing the list
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

// Try to load and register module
struct module *load_and_register_module(const char *module_name)
{
  struct module *mod;

  mutex_lock(&module_mutex);
  mod = find_module(module_name);

  if (!mod)
    {
      mutex_unlock(&module_mutex);
      // Module was not found, try to load it
      if (request_module(module_name))
        {
          // Failed, return 
            return NULL;
        }

        mutex_lock(&module_mutex);
        // Now we try again to see if module is there
        mod = find_module(module_name);
    }
  // Register the module
  if (mod)
    {
      if (!try_module_get(mod))
        {
          // Registration failed
          mod = NULL;
        }
    }
  mutex_unlock(&module_mutex);

  return mod;
}

// De-register module
int unregister_module(const char *module_name)
{
  struct module *mod;
  int ret = 0;

  mutex_lock(&module_mutex);
  mod = find_module(module_name);
  mutex_unlock(&module_mutex);
  if (mod)
    {
      module_put(mod);
      ret = 1;
    }

  return ret;
}
