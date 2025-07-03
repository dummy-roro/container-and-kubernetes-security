# container-and-kubernetes-security

Container?
Isolation in the same system with unique namespaces.

PID - Isolation of process ids
User - Isolation of users & UIDs
Mount - Isolation of mount points
Net - Isolation of networking interfaces & environment
UTS - Isolation of hostname
IPC - Isolation of IPC traffic
Cgroup - Isolation of cgroups (memory & cpu)
https://github.com/rewanthtammana/containers-from-scratch/blob/master/main.go#L32

docker run --rm -it ubuntu bash
# sleep 1d
ps -ef | grep sleep 1d
ls /proc/<PID>/ns
You can see the docker container namespaces! In real all the data, processes, etc are existing on the host machine.

docker run --name debugcontainer --rm -it ubuntu bash
# echo "inside container" > file.txt
docker inspect debugcontainer | grep -i upperdir
In docker inspect, you will see the below fields.

LowerDir: contains the files of the base system UpperDir: all changes to the base system are stored in upperDir

docker inspect debugcontainer | grep -i upperdir
cat <upperdir>/file.txt
Viola! The file you created inside the container is accessible from the host machine.

What does it mean to be root inside a container?
You can run these on killercoda!

Root on host machine & root inside container

$ docker run --rm -it nginx bash
# sleep 1d
$ ps -ef | grep sleep
Non-root on host machine & root inside container

$ adduser ubuntu
$ sudo chown ubuntu:ubuntu /var/run/docker.sock
$ su - ubuntu
$ docker run --rm -it nginx bash
# sleep 2d
$ ps -ef | grep sleep
Root on host machine & non-root inside container

$ docker run --rm --user 1000:1000 -it nginx bash
# sleep 3d
$ ps -ef | grep sleep
Since docker daemon runs as root, eventually all the processes triggered by it run as root. Another example -

echo "I'm root" >> /tmp/groot.txt
chmod 0600 /tmp/groot.txt
su - ubuntu
cat /tmp/groot.txt
docker run --rm -it -v /tmp/groot.txt:/tmp/groot.txt nginx cat /tmp/groot.txt
docker run --rm -it -u 1000:1000 -v /tmp/groot.txt:/tmp/groot.txt nginx cat /tmp/groot.txt
When the user inside the container is non-root, even if the container gets compromised, the attacker cannot read the mounted sensitive files unless they have the appropriate permissions or escalate the privileges.

Privileged container
Kernel files are crucial on host machine, let's see if we can mess with that.

https://github.com/torvalds/linux/blob/v5.0/Documentation/sysctl/vm.txt#L809

$ cat /proc/sys/vm/swappiness
$ docker run --rm --privileged -it ubuntu bash
# cat /proc/sys/vm/swappiness
60
# echo 10 > /proc/sys/vm/swappiness
$ cat /proc/sys/vm/swappiness
These kind of changes to the kernel files can create DoS attacks!

Let's say you got access to one of the containers by exploiting an application or some other means. How will you identify if you are inside a privileged or normal container? There are many ways! A few of them are!

Run two containers, one normal & one privileged

docker run --rm -it ubuntu bash
docker run --rm --privileged -it ubuntu bash
Check for mount permissions & masking
mount | grep 'ro,'
mount | grep /proc.*tmpfs
Linux capabilities - we will see more about it in the next section!
capsh --print
Seccomp - Limit the syscalls
grep Seccomp /proc/1/status
Capabilities
https://command-not-found.com/capsh https://man7.org/linux/man-pages/man7/capabilities.7.html https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/

capsh --print
grep Cap /proc/self/status
capsh --decode=<decodeBnd>
Demonstrating that the processes inside the container inherits it's capabilities

$ docker run --rm -it ubuntu sleep 1d &
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
$ docker run --rm --privileged -it ubuntu sleep 2d &
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
$ docker run --rm --cap-drop=all -it ubuntu sleep 3d &
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
CapEff: The effective capability set represents all capabilities the process is using at the moment.

CapPrm: The permitted set includes all capabilities a process may use.

CapInh: Using the inherited set all capabilities that are allowed to be inherited from a parent process can be specified.

CapBnd: With the bounding set its possible to restrict the capabilities a process may ever receive.

CapAmb: The ambient capability set applies to all non-SUID binaries without file capabilities.

About a few capabilities:

CAP_CHOWN - allows the root use to make arbitrary changes to file UIDs and GIDs

CAP_DAC_OVERRIDE - allows the root user to bypass kernel permission checks on file read, write and execute operations.

CAP_SYS_ADMIN - Most powerful capability. It allows to manage cgroups of the system, thereby allowing you to control system resources

docker run --rm -it busybox:1.28 ping google.com
docker run --rm --cap-drop=NET_RAW -it busybox:1.28 ping google.com
docker run --rm -it --cap-drop=all ubuntu chown nobody /tmp
docker run --rm -it ubuntu chown nobody /tmp
docker run --rm -it --cap-drop=all --cap-add=chown ubuntu chown nobody /tmp
https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/
https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd

Trivy - Scan docker images
https://github.com/aquasecurity/trivy

Visit the latest releases section & install the binary!

trivy i nginx
Since, you have learnt argocd. I will teach you how to fix issues in argocd!

This will not work on killercoda due to disk space constraints, use your local machine to try it!

git clone https://github.com/argoproj/argo-cd
cd argo-cd
# Errors due to BUILDPLATFORM specification, just remove it from the Dockerfile!
docker build . -t argocd
trivy i argocd
It will take sometime to build, so let's review multi-stage builds for a while.

https://github.com/argoproj/argo-cd/blob/master/Dockerfile

Change the base image in the dockerfile, rebuild the argocd image & then scan it. Most of the issues will be sorted out!

https://docs.docker.com/develop/develop-images/multistage-build/

trivy i ubuntu:22.04
trivy i ubuntu:21.10
trivy i ubuntu:21.04
Distroless images

https://github.com/GoogleContainerTools/distroless

trivy i gcr.io/distroless/static-debian11
docker run --rm -it gcr.io/distroless/static-debian11 sh
docker run --rm -it gcr.io/distroless/static-debian11 ls
docker run --rm -it gcr.io/distroless/static-debian11 id
docker run --rm -it gcr.io/distroless/static-debian11 whoami
Analyzing docker images
docker pull ubuntu
docker inspect ubuntu
But the above inspect command will not help you to examine the layers of the docker images
