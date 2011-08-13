/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_APACHE_LICENSE_HEADER_START@
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

static const char *const __rcs_file_version__ = "$Revision: 23930 $";

#include "config.h"
#include "launch.h"
#include "launch_priv.h"
#include "bootstrap.h"
#include "vproc.h"
#include "vproc_priv.h"
#include "vproc_internal.h"
#include "bootstrap_priv.h"
#include "launch_internal.h"

#include <CoreFoundation/CoreFoundation.h>
//#include <CoreFoundation/CFPriv.h>
//#include <CoreFoundation/CFLogUtilities.h>
#include <TargetConditionals.h>
#if HAVE_SECURITY
#include <Security/Security.h>
#include <Security/AuthSession.h>
#endif
#include <IOKit/IOKitLib.h>
#include <NSSystemDirectories.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifndef SO_EXECPATH
/* This is just so it's easy for me to compile launchctl without buildit. */
	#define SO_EXECPATH 0x1085
#endif
#include <sys/un.h>
#include <sys/fcntl.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
//#include <netinet6/nd6.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <syslog.h>
#include <glob.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <dns_sd.h>
#include <paths.h>
#include <utmpx.h>
//#include <bootfiles.h>
#include <sysexits.h>
#include <util.h>
#include <spawn.h>
#include <sys/syslimits.h>

/*
#if HAVE_LIBAUDITD
#include <bsm/auditd_lib.h>
#ifndef	AUDITD_PLIST_FILE
#define	AUDITD_PLIST_FILE "/System/Library/LaunchDaemons/com.apple.auditd.plist"
#endif
#endif
*/

extern char **environ;


#define LAUNCH_SECDIR _PATH_TMP "launch-XXXXXX"

#define MACHINIT_JOBKEY_ONDEMAND	"OnDemand"
#define MACHINIT_JOBKEY_SERVICENAME	"ServiceName"
#define MACHINIT_JOBKEY_COMMAND		"Command"
#define MACHINIT_JOBKEY_SERVERPORT	"ServerPort"
#define MACHINIT_JOBKEY_SERVICEPORT	"ServicePort"

#define assumes(e)	\
	(__builtin_expect(!(e), 0) ? _log_launchctl_bug(__rcs_file_version__, __FILE__, __LINE__, #e), false : true)

#define CFTypeCheck(cf, type) (CFGetTypeID(cf) == type ## GetTypeID())


static mach_port_t str2bsport(const char *s);
static pid_t fwexec(const char *const *argv, int *wstatus);


pid_t
fwexec(const char *const *argv, int *wstatus)
{
        int wstatus2;
        pid_t p;

        /* We'd use posix_spawnp(), but we want to workaround: 6288899 */

        if ((p = vfork()) == -1) {
                return -1;
        } else if (p == 0) { 
                execvp(argv[0], (char *const *)argv);
                _exit(EXIT_FAILURE);
        }    

        if (waitpid(p, wstatus ? wstatus : &wstatus2, 0) == -1) {
                return -1;
        }    

        if (wstatus) {
                return p;
        } else if (WIFEXITED(wstatus2) && WEXITSTATUS(wstatus2) == EXIT_SUCCESS) {
                return p;
        }    

        return -1;
}

mach_port_t
str2bsport(const char *s)
{
	bool getrootbs = strcmp(s, "/") == 0;
	mach_port_t last_bport, bport = bootstrap_port;
	task_t task = mach_task_self();
	kern_return_t result;

	if (strcmp(s, "..") == 0 || getrootbs) {
		do {
			last_bport = bport;
			result = bootstrap_parent(last_bport, &bport);

			if (result == BOOTSTRAP_NOT_PRIVILEGED) {
				fprintf(stderr, "Permission denied\n");
				return 1;
			} else if (result != BOOTSTRAP_SUCCESS) {
				fprintf(stderr, "bootstrap_parent() %d\n", result);
				return 1;
			}
		} while (getrootbs && last_bport != bport);
	} else if( strcmp(s, "0") == 0 || strcmp(s, "NULL") == 0 ) {
		bport = MACH_PORT_NULL;
	} else {
		int pid = atoi(s);

		result = task_for_pid(mach_task_self(), pid, &task);

		if (result != KERN_SUCCESS) {
			fprintf(stderr, "task_for_pid() %s\n", mach_error_string(result));
			return 1;
		}

		result = task_get_bootstrap_port(task, &bport);

		if (result != KERN_SUCCESS) {
			fprintf(stderr, "Couldn't get bootstrap port: %s\n", mach_error_string(result));
			return 1;
		}
	}

	return bport;
}

int
bsexec(int argc, char *const argv[])
{
        kern_return_t result;
        mach_port_t bport;

        if (argc < 3) { 
                fprintf(stderr, "usage: %s bsexec <PID> prog...\n", getprogname());
                return 1;
        }    

        bport = str2bsport(argv[1]);

        result = task_set_bootstrap_port(mach_task_self(), bport);

        if (result != KERN_SUCCESS) {
                fprintf(stderr, "Couldn't switch to new bootstrap port: %s\n", mach_error_string(result));
                return 1;
        }    

        setgid(getgid());
        setuid(getuid());

        if (fwexec((const char *const *)argv + 2, NULL) == -1) {
                fprintf(stderr, "%s bsexec failed: %s\n", getprogname(), strerror(errno));
                return 1;
        }    

        return 0;
}
