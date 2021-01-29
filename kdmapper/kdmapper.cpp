#include "kdmapper.hpp"
#include "bcrypt.h"
#pragma comment (lib, "bcrypt.lib")

uint64_t kdmapper::MapDriver(HANDLE iqvw64e_device_handle, const std::string& driver_path)
{
	std::vector<uint8_t> raw_image = {0};

	if (!utils::ReadFileToMemory(driver_path, &raw_image))
	{
		std::cout << xorstr_("[-] Failed to read image to memory") << std::endl;
		return 0;
	}

	const auto nt_headers = portable_executable::GetNtHeaders(raw_image.data());

	if (!nt_headers)
	{
		std::cout << xorstr_("[-] Invalid or non-x64 PE image") << std::endl;
		return 0;
	}

	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

	auto local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	auto kernel_image_base = intel_driver::AllocatePool(iqvw64e_device_handle, nt::NonPagedPool, image_size);

	do
	{
		if (!kernel_image_base)
		{
			std::cout << xorstr_("[-] Failed to allocate remote image in kernel") << std::endl;
			break;
		}

		std::cout << xorstr_("[+] Image base has been allocated at 0x") << reinterpret_cast<void*>(kernel_image_base) <<
			std::endl;

		// Copy image headers

		memcpy(local_image_base, raw_image.data(), nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const auto section_headers = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			if ((section_headers[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
				) != 0 &&
				section_headers[i].PointerToRawData != 0)
			{
				const auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) +
					section_headers[i].VirtualAddress);
				memcpy(local_section,
				       reinterpret_cast<void*>(reinterpret_cast<uint64_t>(raw_image.data()) + section_headers[i].
					       PointerToRawData), section_headers[i].SizeOfRawData);
			}
		}

		// Initialize stack cookie if driver was compiled with /GS

		InitStackCookie(local_image_base);

		// Resolve relocs and imports

		// A missing relocation directory is OK, but disallow IMAGE_FILE_RELOCS_STRIPPED
		// Not checked: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE in DllCharacteristics. The DDK/WDK has never set this mostly for historical reasons
		const auto& relocs = portable_executable::GetRelocs(local_image_base);
		if (relocs.empty() && (nt_headers->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)
		{
			std::cout << xorstr_("[-] Image is not relocatable") << std::endl;
			break;
		}

		RelocateImageByDelta(relocs, kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base)))
		{
			std::cout << xorstr_("[-] Failed to resolve imports") << std::endl;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::WriteMemory(iqvw64e_device_handle, kernel_image_base, local_image_base, image_size))
		{
			std::cout << xorstr_("[-] Failed to write local image to remote image") << std::endl;
			break;
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);

		// Call driver entry point

		const auto address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		std::cout << xorstr_("[>] Filling driver PE headers with junk") << std::endl;

		auto randBuf = VirtualAlloc(nullptr, nt_headers->OptionalHeader.SizeOfHeaders, MEM_RESERVE | MEM_COMMIT,
		                            PAGE_READWRITE);

		if (BCryptGenRandom(
			nullptr,
			static_cast<PUCHAR>(randBuf),
			nt_headers->OptionalHeader.SizeOfHeaders,
			BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		{
			std::cout << xorstr_("[-] Failed clearing PE headers: ") << std::endl;
			break;
		}

		intel_driver::MemCopy(iqvw64e_device_handle, kernel_image_base, reinterpret_cast<uint64_t>(randBuf),
		                      nt_headers->OptionalHeader.SizeOfHeaders);

		std::cout << xorstr_("[<] Calling DriverEntry 0x") << reinterpret_cast<void*>(address_of_entry_point) << std::
			endl;

		NTSTATUS status = 0;

		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point,
		                                      kernel_image_base))
		{
			std::cout << xorstr_("[-] Failed to call driver entry") << std::endl;
			break;
		}

		std::cout << xorstr_("[+] DriverEntry returned 0x") << std::hex << std::setw(8) << std::setfill('0') << std::
			uppercase << status << std::nouppercase << std::dec << std::endl;

		return kernel_image_base;
	}
	while (false);

	VirtualFree(local_image_base, 0, MEM_RELEASE);
	// Entry is removed from BigPoolTable, thus not freed
	//intel_driver::FreePool(iqvw64e_device_handle, kernel_image_base);

	return 0;
}

void kdmapper::RelocateImageByDelta(const portable_executable::vec_relocs& relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i)
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, const portable_executable::vec_imports& imports)
{
	for (const auto& current_import : imports)
	{
		//std::cout << "Resolving " << current_import.module_name << std::endl;

		if (!utils::GetKernelModuleAddress(current_import.module_name))
		{
			std::cout << xorstr_("[-] Dependency ") << current_import.module_name << xorstr_(" wasn't found") << std::
				endl;
			return false;
		}

		for (auto& current_function_data : current_import.function_datas)
		{
			const auto function_address = intel_driver::GetKernelModuleExport(
				iqvw64e_device_handle, utils::GetKernelModuleAddress(current_import.module_name),
				current_function_data.name);

			if (!function_address)
			{
				std::cout << xorstr_("[-] Failed to resolve import ") << current_function_data.name << xorstr_(" (") <<
					current_import.module_name << xorstr_(")") << std::endl;
				return false;
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

void kdmapper::InitStackCookie(void* base)
{
	const auto nt_headers = RtlImageNtHeader(base);
	ULONG config_dir_size = 0;
	const auto config_dir = static_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(
		RtlImageDirectoryEntryToData(base,
		                             TRUE,
		                             IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
		                             &config_dir_size));
	if (config_dir == nullptr || config_dir_size == 0)
		return;

	uint64_t cookie_va;
	if ((cookie_va = static_cast<uint64_t>(config_dir->SecurityCookie)) == 0)
		return;
	cookie_va = cookie_va - nt_headers->OptionalHeader.ImageBase + reinterpret_cast<uint64_t>(base);

	auto cookie = SharedUserData->SystemTime.LowPart ^ cookie_va;
	cookie &= 0x0000FFFFFFFFFFFFi64;

	constexpr const auto default_security_cookie64 = 0x00002B992DDFA232ULL;
	if (static_cast<uint64_t>(cookie) == default_security_cookie64)
		cookie++;

	// Guess the address of the complement (normally correct for MSVC-compiled binaries)
	auto cookie_complement_va = cookie_va + sizeof(uint64_t);
	if (*reinterpret_cast<uint64_t*>(cookie_complement_va) != ~default_security_cookie64)
	{
		// Nope; try before the cookie instead
		cookie_complement_va = cookie_va - sizeof(uint64_t);
		if (*reinterpret_cast<uint64_t*>(cookie_complement_va) != ~default_security_cookie64)
			cookie_complement_va = 0;
	}

	*reinterpret_cast<uint64_t*>(cookie_va) = cookie;
	if (cookie_complement_va != 0)
		*reinterpret_cast<uint64_t*>(cookie_complement_va) = ~cookie;
}
