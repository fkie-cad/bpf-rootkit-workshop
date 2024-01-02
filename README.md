# DFRWS EU 2023 Workshop: Forensic Analysis of eBPF based Linux Rootkits

Materials for the Workshop [_Forensic Analysis of eBPF based Linux Rootkits_](https://dfrws.org/forensic-analysis-of-ebpf-based-linux-rootkits/) that our colleagues [Martin Clauß](https://github.com/martinclauss/) and [Valentin Obst](https://github.com/vobst) gave at the DFRWS EU 2023 conference. We have published a blog post that covers some of the materials [here](https://blog.eb9f.de/2023/12/21/bpf_memory_forensics_with_volatility_3.html), and the presented Volatility 3 plugins are available [here](https://github.com/vobst/BPFVol3).

## Structure

This is a three-part workshop: introduction, live forensics, and memory forensics. We do not expect you to have any prior knowledge about the BPF subsystem and thus introduce the necessary prerequisites in part one. Part two covers tools and techniques to discover BPF malware from a shell running on the system under investigation. In the third part, we discuss methods to analyze memory images for malicious activities in the BPF subsystem. The slides are located at the root of each subdirectory.

Every part contains several practical exercises. All the materials needed to solve the problems can be found in the `materials` folder and the solutions can be found in the `solutions` folder.

## Downloads

Certain workshop materials are unsuitable for storage in a git repository. Below are links to download them from external sources.

### Virtual Machines

In the slides we mention two virtual machines.

- The Kali Linux VM contains these materials as well as all required third-party tools and can be used to complete the workshop if the operating system does not support BPF, e.g., in case you use a hardened Linux kernel or any other operating system (BSD, Mac, Windows...). [Download](https://uni-bonn.sciebo.de/s/8r2QKoJccLQLeyo)
- The Ubuntu VM is used during the live forensics exercise. [Download](https://uni-bonn.sciebo.de/s/8r2QKoJccLQLeyo)

### Memory Images and Symbols

In the memory forensics part, there are multiple exercises where you have to analyze memory images. [Download](https://owncloud.fraunhofer.de/index.php/s/IeriGoh60FXVpd9)

To analyze them with Volatility you also need the corresponding symbol files. [Download](https://owncloud.fraunhofer.de/index.php/s/Zf74POYNrKvB7Xg)

### Packet Captures

Some exercises involve the analysis of pcap files. [Download](https://owncloud.fraunhofer.de/index.php/s/u5oG91ZP7HnUxJw)
