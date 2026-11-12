# Appendix H — Adding the Evidence Disk to Your Lab VM

Chapter 1 §1.4.4, Lab 1 Task 1.2 and Lab 1.4 Task 3 all ask for a second virtual disk, mounted as `E:`. Every hypervisor puts that setting in a different place, so this appendix gives the steps for each one. Read H.1 first, then follow the section for your hypervisor. Next, prepare the disk inside Windows (H.6) and find its file on your host so you can hash it (H.7). H.8 covers the problems readers hit most often.

## H.1 Choose the Disk Settings

Shut the VM down completely before you change its hardware. A suspended VM keeps its old hardware list, and some hypervisors refuse to add a disk while the VM runs. Shut down from inside Windows with **Start → Power → Shut down**, not by closing the hypervisor window.

Use the same disk settings whichever hypervisor you run:

| Setting | Value | Why |
|---|---|---|
| Size | 40 GB | Room for the Lab 1 sample files plus the collections later labs write to `E:` |
| Allocation | Dynamic, which some hypervisors call thin or expanding | The file starts small and grows only as you fill the disk |
| Storage | One file, not split into pieces | Lab 1 Task 1.3 hashes a single file |
| File name | `Evidence`, plus the extension the hypervisor adds | Easy to find on the host and to name in the chain-of-custody record |
| Controller | The type the hypervisor recommends | Windows already has a driver for it |

Task 1.1 took the `OS-Only` snapshot before this disk existed. The new disk is not part of that snapshot, so it does not affect the hash you take in Task 1.3.

## H.2 Add the Disk in VMware Workstation Pro

VMware Workstation Pro runs on Windows and Linux hosts and is free to use. Add the disk from the VM's settings:

1. Select the VM in the library and open **VM → Settings**.
2. On the **Hardware** tab, click **Add**. Select **Hard Disk** and click **Next**.
3. Keep the disk type the wizard marks as recommended, such as **NVMe** or **SCSI**, and click **Next**.
4. Select **Create a new virtual disk** and click **Next**.
5. Set **Maximum disk size** to 40 GB. Leave **Allocate all disk space now** cleared. Select **Store virtual disk as a single file** and click **Next**.
6. Name the file `Evidence.vmdk`. Workstation saves it in the VM's folder. Click **Finish**, then **OK**.

VMware Fusion on a Mac uses the same settings. Its path is **Virtual Machine → Settings → Add Device → New Hard Disk**.

## H.3 Add the Disk in VirtualBox

VirtualBox runs on Windows, Linux and Intel-based Mac hosts. In VirtualBox 7, you create the disk from the VM's storage settings. The wizard pages differ slightly between 7.0 and 7.1, but the choices are the same:

1. Select the VM and click **Settings**, then **Storage**.
2. Select the controller that holds the system disk, usually **SATA**. Click the **Adds hard disk** icon on that controller's row.
3. In the **Hard Disk Selector**, click **Create**.
4. Choose **VDI** and leave **Pre-allocate Full Size** cleared. Set the size to 40 GB and the name to `Evidence.vdi`, then click **Finish**.
5. Select `Evidence.vdi` in the selector and click **Choose**, then **OK**.

To script the same change, use `VBoxManage` on the host. Run `VBoxManage showvminfo "DFIR-LAB-01"` first. Its storage section lists each controller's name and the ports already in use, so you can pick a free port for `--port`:

```
VBoxManage createmedium disk --filename "C:\Users\you\VirtualBox VMs\DFIR-LAB-01\Evidence.vdi" --size 40960 --format VDI
VBoxManage storageattach "DFIR-LAB-01" --storagectl "SATA" --port 2 --device 0 --type hdd --medium "C:\Users\you\VirtualBox VMs\DFIR-LAB-01\Evidence.vdi"
```

`--size` takes megabytes, so 40960 is 40 GB. Replace `DFIR-LAB-01`, the path and the controller name with your own.

## H.4 Add the Disk in Hyper-V

Hyper-V ships with the Pro, Enterprise and Education editions of Windows 10 and 11. Windows 11 VMs are Generation 2 and attach data disks to the SCSI controller:

1. In Hyper-V Manager, right-click the VM and select **Settings**.
2. Select **SCSI Controller**. On a Generation 1 VM, select **IDE Controller 1** instead.
3. Select **Hard Drive** and click **Add**.
4. Under **Virtual hard disk**, click **New** to open the New Virtual Hard Disk Wizard.
5. If the wizard asks for a format, choose **VHDX**. Choose **Dynamically expanding**.
6. Name the file `Evidence.vhdx`, set the size to 40 GB, and click **Finish**. Click **OK** to close Settings.

The same change in PowerShell, from an administrator prompt on the host:

```powershell
$vhd = Join-Path (Get-VMHost).VirtualHardDiskPath 'Evidence.vhdx'
New-VHD -Path $vhd -SizeBytes 40GB -Dynamic
Add-VMHardDiskDrive -VMName 'DFIR-LAB-01' -ControllerType SCSI -Path $vhd
```

`(Get-VMHost).VirtualHardDiskPath` returns the host's default disk folder, the same folder the wizard offers.

## H.5 Add the Disk in UTM or Parallels Desktop on a Mac

Apple silicon Macs run Windows 11 on Arm, not the x64 Windows that most forensic tools target. Windows on Arm runs most x64 applications through emulation, but it cannot load x64 kernel drivers. Memory-capture tools and image mounters depend on such drivers, so check each one for Arm64 support. Run the Lab 1 Task 1.6 smoke test before you rely on any tool, and record failures in your tool checklist.

**UTM:**

1. Shut down the VM, select it in the UTM window, and open its settings with the **Edit** button.
2. In the sidebar, add a new drive. The button sits under the **Drives** list.
3. Set **Interface** to **NVMe** and leave **Removable** cleared. Set the size to 40 GB and create the drive.
4. Click **Save**.

NVMe uses a driver built into Windows. A VirtIO drive also works, but only after you install the VirtIO drivers inside the guest.

**Parallels Desktop:**

1. Shut down the VM. In Control Center, click the gear icon next to it to open its configuration.
2. Click **Hardware**. Click the **+** button below the device list and choose **Hard Disk**.
3. Keep **Type** set to **New image file**. Set the size to 40 GB, keep the disk expanding, and click **OK**.

## H.6 Prepare the Disk Inside Windows

Start the VM and sign in as an administrator. Windows sees the new disk as raw space with no partitions. Disk Management turns it into the `E:` volume:

1. Press **Win+X** and select **Disk Management**.
2. When the **Initialize Disk** dialog opens, choose **GPT** and click **OK**. If the dialog does not open, right-click the disk marked **Not Initialized** and select **Initialize Disk**. MBR also works for a lab disk.
3. Right-click the unallocated space on the new disk and select **New Simple Volume**.
4. Accept the full size and assign drive letter **E**. Format the volume as **NTFS** with the label `EVIDENCE`, keep **Perform a quick format** selected, and click **Finish**.

If **E** is not in the drive-letter list in step 4, another device holds it, usually the virtual DVD drive. Right-click that device in Disk Management and select **Change Drive Letter and Paths**. Move it to a later letter such as `R:`, then repeat step 4.

The same steps as one PowerShell pipeline, from an administrator prompt inside the VM:

```powershell
Get-Disk | Where-Object PartitionStyle -eq 'RAW' |
  Initialize-Disk -PartitionStyle GPT -PassThru |
  New-Partition -DriveLetter E -UseMaximumSize |
  Format-Volume -FileSystem NTFS -NewFileSystemLabel EVIDENCE
```

Run `Get-Disk` on its own first. The pipeline formats every raw disk it finds, so confirm that the new disk is the only one marked `RAW`.

## H.7 Find and Hash the Disk File

Lab 1 Task 1.3 hashes the disk file on the host. Shut the VM down first. A running VM holds the file open and keeps writing to it, so a hash taken while it runs proves nothing.

Ask the hypervisor where it put the file rather than guessing at a default folder:

| Hypervisor | How to find the file | File to hash |
|---|---|---|
| VMware Workstation Pro | VM Settings → the new hard disk. The **Disk file** field shows the name, and the file sits in the VM's folder | `Evidence.vmdk` |
| VirtualBox | Settings → Storage → select `Evidence.vdi`. The **Location** field shows the full path | `Evidence.vdi` |
| Hyper-V | `Get-VMHardDiskDrive -VMName 'DFIR-LAB-01' \| Select-Object Path` on the host | `Evidence.vhdx` |
| UTM | Right-click the VM → **Show in Finder**, then **Show Package Contents** and open `Data` | The newest `.qcow2` file. UTM names drive files by ID, not by your label |
| Parallels Desktop | Right-click the VM in Control Center → **Show in Finder**, then **Show Package Contents** | The `.hds` file inside the new disk's `.hdd` folder |

Hash the file with the tool your host provides:

| Host | Command |
|---|---|
| Windows | `Get-FileHash -Algorithm SHA256 'C:\path\to\Evidence.vmdk'` |
| macOS | `shasum -a 256 /path/to/file` |
| Linux | `sha256sum /path/to/file` |

Two behaviors change the hash, and both are lessons rather than failures:

- **Booting the VM changes the file.** Windows writes to an NTFS volume as soon as it mounts it, even if you open nothing. A hash you record in Task 1.3 describes the disk only until the next boot. Real acquisitions use write blockers for exactly this reason.
- **A snapshot redirects writes.** Once you take a snapshot or checkpoint, the hypervisor freezes the original file and writes later changes to a differencing file. VMware writes to files such as `Evidence-000001.vmdk`, VirtualBox to a file in the VM's `Snapshots` folder, and Hyper-V to an `.avhdx` file. The original file's hash stops changing, but the file no longer holds the disk's current state. Task 1.3 runs before the `Baseline-Clean` snapshot in Task 1.7, so the original file is still current when you hash it.

## H.8 Fix Common Problems

Most disk problems trace back to the VM's power state or to drive letters:

| Symptom | Likely cause | Fix |
|---|---|---|
| Disk Management shows no new disk | The VM was suspended rather than shut down, or you added the disk to a different VM | Shut down fully, confirm the disk appears in this VM's settings, and boot again |
| A UTM drive does not appear in Windows | The drive uses the VirtIO interface, and the guest has no VirtIO driver | Change the drive's interface to NVMe |
| The new disk shows as **Offline** | Windows keeps new disks offline under some SAN policies, most often on Windows Server | Right-click the disk's label in Disk Management and select **Online** |
| Drive letter E is not offered | The virtual DVD drive or another volume already holds `E:` | Move that device to another letter, as H.6 describes |
| Two hashes differ, and you did not boot the VM between them | The VM was running or suspended during one of the hashes | Shut down fully, close the hypervisor, and hash twice more |
| The hash changed after you booted the VM | Expected: Windows wrote to the volume when it mounted it | Record the new hash and note the boot as the reason in your chain-of-custody record |

---

*End of Appendix H.*

---
