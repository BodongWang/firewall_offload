# Introduction

Application to communicate with firewall via grpc, and do HW offload on Nvidia
BlueField DPU

# Prerequisite

1. Create 2 VFs for each PF on x86 side
2. An option configure file can be added to __/opt/mellanox/opof/opof.conf__
with json format. For example:

```
{
  "grpc_addr":"169.254.33.51"
  "grpc_port":3443
}
```

# Building

Dependency:
    libev (e.g, yum install -y libev libev-devel)

To build and install this daemon with all deps, run:
```sh
$ ./build.sh
```

To only build the daemon with preconfigured deps(grpc/sessionOffload)
```sh
$ export PKG_CONFIG_PATH=/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig/
$ make && make install
```
Setup hugepages
```sh
$ mkdir -p /dev/hugepages
$ mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages
$ echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
```

# Usage
The controller has a systemd service running and a user interface tool to
communicate with the service.

* Service: opof.service
* User Interface: opof
* Log: __journalctl -u opof -f__

## Setup

User can run __opof_setup__ to setup opof.

1. As default, the script does configures below:
* Configure OVS fallback bridges. So that, when daemon is failed or killed,
  all traffic will be forward to PAN-OS for processing.
* Configure gRPC interface(default pf0vf1) IP address.
* Reserve hugepages, default 2048 * 2M.

2. User can specify the number of HugePages
```sh
$ opof_setup -p 2048
```
3. User can specify the interface used by grpc
```sh
$ opof_setup -g pf1vf1
```

## SystemD Service

If daemon is running on a DPU, most likely the service already started
automatically. Run command below to check the status.

```sh
$ systemctl status opof.service
```

If daemon is not running, start controller by running command below.
Make sure to check the status after command start.

```sh
$ systemctl start opof.service
```

To restart the daemon, run

```sh
$ systemctl restart opof.service
```
## User Interface

Each command has its own help manual, e.g, _opof query -h_

1. Query a session

```sh
$ opof query -i <session_id>
```

2. Query daemon offload stats

```sh
$ opof stats
```
