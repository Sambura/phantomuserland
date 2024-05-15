/*
 * Envrionment for Phantom OS
 * Based on rm_nested example and rump block device backend
 */

#include <base/component.h>
#include <rm_session/connection.h>
#include <region_map/client.h>
#include <dataspace/client.h>

#include <base/allocator_avl.h>
#include <block_session/connection.h>

// #include <libc/component.h>

#include "phantom_env.h"
#include "disk_backend.h"
#include "phantom_vmem.h"

#include "phantom_entrypoints.h"

#include "tests_hal.h"
#include "tests_adapters.h"

#include <base/quota_guard.h>

namespace Genode {
	bool phantom_quota_go = false;
}

Phantom::Main *Phantom::main_obj = nullptr;

void setup_adapters(Env &env)
{
	static Phantom::Main local_main(env);
	Phantom::main_obj = &local_main;
}

Genode::size_t Component::stack_size() {
    return 60 * 1024 * sizeof(long);
}


void test_adapters()
{
	log("Checking if main_obj is initialized");
	log(&Phantom::main_obj->_vmem_adapter);

	// log("Start obj_space test!");
	// Phantom::test_obj_space();
	// log("Finished obj_space test!");

	log("Starting remapping test!");
	Phantom::test_remapping();
	log("finished remapping test!");

	log("Starting block device test!");
	// Phantom::test_block_device_adapter(Phantom::main_obj->_disk);
	// Phantom::test_block_alignment(Phantom::main_obj->_disk);
	log("Finished block device test!");

	log("Starting bulk code test!");
	Phantom::test_bulk();
	log("finished bulk code test!");
}

bool test_hal()
{
	bool ok = true;

	// Phantom::test_hal_vmem_alloc();
	// XXX : Commented since allocating only vmem is not supported
	// log("--- Starting vmem alloc test");
	// if (!test_hal_vmem_alloc())
	// {
	// 	ok = false;
	// 	log("Failed vmem alloc test!");
	// }

	log("--- Starting phys alloc test");
	if (!test_hal_phys_alloc())
	{
		ok = false;
		log("Failed phys alloc test!");
	}

	log("--- Starting virt addrs mapping test");
	if (!test_hal_vmem_mapping())
	{
		ok = false;
		log("Failed virt addrs mapping test!");
	}

	log("--- Starting virt addrs remapping test");
	if (!test_hal_vmem_remapping())
	{
		ok = false;
		log("Failed virt addrs remapping test!");
	}

	log("--- Starting mutex states test");
	if (!test_hal_mutex_state())
	{
		ok = false;
		log("Failed mutex states test!");
	}

	return ok;
}

// extern "C" void wait_for_continue(void);

// void Libc::Component::construct(Libc::Env &env)
void Component::construct(Env &env)
{

	// Libc::with_libc([&]()
	// 				{
	// 	int p_argc = 1;
	// 	char **p_argv = nullptr;
	// 	char **p_envp = nullptr;
	// 	phantom_main_entry_point(p_argc, p_argv, p_envp); });

	// void *f_addr = 0x0;
	// log(*((int *)f_addr));

	// Libc::with_libc([&]()
	// 				{
		log("--- Phantom init ---");
		log("short size: ", sizeof(short));
		log("int size: ", sizeof(int));
		log("long size: ", sizeof(long));
		log("long long size: ", sizeof(long long));

		env.exec_static_constructors();

		
		// Ram_dataspace_capability test_ds = env.ram().alloc(20 * 1024 * 4096);
    	// Genode::Region_map_client _obj_space{_rm.create(OBJECT_SPACE_SIZE)};
		
		// for (unsigned long i=0;i<2000;i++){
		// 	Genode::log("Attaching (root) ", i);
		// 	// env.rm().attach_at(test_ds, 0x8000000 + i*4096, 4096, i*4096);
		// 	env.rm().attach(test_ds, 4096);
		// }




		log("Waiting for continue");
		// wait_for_continue();
		log("GO");

		{
			/*
			 * Setup Main object
			 */
			try
			{
				log("--- Setting up adapters ---");
				setup_adapters(env);
			}
			catch (Genode::Service_denied)
			{
				error("opening block session was denied!");
				return;
			}
		}

		// log("--- TESTING LOTS OF ATTACH ---");

		// Dataspace_capability test_ds_2 = env.ram().alloc(20 * 1024 * 4096);
		// for (unsigned long i=0;i<300;i++){
		// 	Genode::log("Attaching ", i);
        //     if (i == 244){
        //         Genode::log("Should fail here");
        //     }
		// 	// main_obj->_vmem _obj_space.attach_at(_ram_ds, i*4096, 4096, i*4096);
		// 	// if (i < 50) {
		// 	// main_obj->_vmem_adapter._obj_space.attach_at(
		// 	// 	main_obj->_vmem_adapter._ram_ds, i*4096, 4096, i*4096);
		// 	// } else {
		// 	main_obj->_vmem_adapter._obj_space.attach_at(
		// 		test_ds_2, i*4096, 4096, i*4096);

		// 	// }
		// 	// env.rm().attach(test_ds, 4096);
		// }



		log("--- Testing adapters ---");
		test_adapters();

		log("--- Testing HAL ---");
		test_hal();

		log("--- finished Phantom env test ---");

		 	// env.exec_static_constructors(); <- This thing might break pthreads!

		// Actual Phantom code

		int p_argc = 1;
		char **p_argv = nullptr;
		char **p_envp = nullptr;

		Genode::phantom_quota_go = true;

		phantom_main_entry_point(p_argc, p_argv, p_envp); 
	// });
}

// int main()
// {
// 	log("What are we doing here???");
// }
