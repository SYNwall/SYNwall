/*
 *
 * SYNwall
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)

/**
 *  find_module - replacement of find_module, removed from kernels >= 5.12
 *  @name: pointer to the string with module name
 */
struct module *find_module(const char *name);

#endif

/**
 *  load_and_register_module - try to locate and register a module
 *  @module_name: name of the module
 *
 *  Try to locate the module, if not found try to load it. 
 *  If everything is good, register the usage of the module and returns
 *  the module structure. Otherwise returns NULL
 *
 */
struct module *load_and_register_module(const char *module_name);

/**
 *  unregister_module - try to locate and unregister a module
 *  @module_name: name of the module
 *
 *  Try to locate the module and if found it remove the references.
 *  Returns 1 if done or 0 otherwise.
 *  To be called only if the module has been registerd with "load_and_register_module"
 *  function.
 *
 */
int unregister_module(const char *module_name);
