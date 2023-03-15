# Disable_nmi_callbacks
# an old code
#

```C

extern "C"
{

	NTSYSAPI BOOLEAN  NTAPI KeInterlockedSetProcessorAffinityEx(PKAFFINITY_EX pAffinity, KEPROCESSORINDEX idxProcessor);

}

bool disable_nmi_callbacks() {
	const auto ntoskrnl_base = (PVOID)utils::get_kernel_module(Crypt("ntoskrnl.exe"));

	if (!ntoskrnl_base) {
		DbgPrintEx(0, 0, Crypt("[-] ntoskrnl_base not found\n"));
		return 0;
	}
	else {
		DbgPrintEx(0, 0, Crypt("[+] ntoskrnl_base @ 0x%p\n"), ntoskrnl_base);

	}
	
	auto nmi_in_progress = reinterpret_cast<uint8_t*>(utils::find_pattern((uintptr_t)ntoskrnl_base, Crypt("\x81\x25\x00\x00\x00\x00\x00\x00\x00\x00\xB9\x00\x00\x00\x00"), Crypt("xx????????x????")));

	if (!nmi_in_progress) {
		DbgPrintEx(0, 0, Crypt("[-] nmi_in_progress not found\n"));
		return 0;
	}
	else {
		DbgPrintEx(0, 0, Crypt("[+] nmi_in_progress @ 0x%p\n"), nmi_in_progress);
	}

	if (nmi_in_progress) {

		while (*nmi_in_progress != 0x48) {
			++nmi_in_progress;
		}

		nmi_in_progress = impl::resolve_mov(nmi_in_progress);

		DbgPrintEx(0, 0, Crypt("[+] nmi_in_progress (resolved) @ 0x%p\n"), nmi_in_progress);

		if (!nmi_in_progress) {
			DbgPrintEx(0, 0, Crypt("[-] !nmi_in_progress\n"));
		}

		auto irql = KfRaiseIrql(0);

		ULONG cores = KeQueryActiveProcessorCount(NULL);

		for (auto i = 0ul; i < cores; ++i) {

			KeInterlockedSetProcessorAffinityEx((PKAFFINITY_EX)nmi_in_progress, i);
			InterlockedBitTestAndSet64((LONG64*)(nmi_in_progress), i); 

			DbgPrintEx(0, 0, Crypt("[+] disabled nmi for proccessor %d\n"), i);

		}

		KeLowerIrql(irql);
	}

	DbgPrintEx(0, 0, Crypt("[+] Done disabled nmi callback\n"));
	return true;

}

```

# Example Usage

```C

extern "C" NTSTATUS DriverEntry() {

	BOOL status = disable_nmi_callbacks();

	if (status == FALSE) {
		DbgPrintEx(0, 0, Crypt("[-] Failed disabling nmi callbacks.\n"));
	}
	else {
		DbgPrintEx(0, 0, Crypt("[+] Done disabled nmi callback\n"));
	}


	DbgPrintEx(0, 0, Crypt("[+] Driver loaded!\n"));

}

```
