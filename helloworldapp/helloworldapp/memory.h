#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>

class c_memory {
private:
	MODULEENTRY32 client_dll;
	MODULEENTRY32 engine_dll;
	unsigned long pid;

public:
	void* csgo;
	HWND window;
	uintptr_t client;
	uintptr_t engine;

	c_memory( void ) {
		while ( !window ) {
			window = FindWindowA( "Valve001", nullptr );
			Sleep( 500 );
		}

		GetWindowThreadProcessId( window, &pid );
		csgo = OpenProcess( PROCESS_ALL_ACCESS, false, pid );

		if ( !csgo )
			exit( 0 );

		while ( !client_dll.modBaseAddr ) {
			client_dll = get_module_by_name( "client.dll" );

			if ( !client_dll.modBaseAddr )
				client_dll = get_module_by_name( "client_panorama.dll" );

			Sleep( 100 );
		}

		while ( !engine_dll.modBaseAddr ) {
			engine_dll = get_module_by_name( "engine.dll" );
			Sleep( 100 );
		}

		client = ( uintptr_t ) client_dll.modBaseAddr;
		engine = ( uintptr_t ) engine_dll.modBaseAddr;
	}

	~c_memory( void ) {
		CloseHandle( csgo );
	}

	template < typename type >
	type read( uintptr_t address ) {
		type r;
		ReadProcessMemory( csgo, ( void* ) address, &r, sizeof( type ), nullptr );
		return r;
	}

	template < typename type >
	bool write( uintptr_t address, type value ) {
		return WriteProcessMemory( csgo, ( void* ) address, &value, sizeof( type ), nullptr );
	}

	void* get_vfunc( void* pp_class, uintptr_t index ) {
		return ( void* ) ( read< uintptr_t >( ( uintptr_t ) pp_class ) + sizeof( uintptr_t ) * index );
	}

	void* hook_vt( void* clazz, uintptr_t index, void* hook_fn ) {
		void* vfunc = get_vfunc( clazz, index );
		unsigned long old_protect;
		VirtualProtectEx( csgo, ( void* ) vfunc, sizeof( void* ), PAGE_EXECUTE_READWRITE, &old_protect );
		void* o_vfunc = read< void* >( ( uintptr_t ) vfunc );
		write< void* >( ( uintptr_t ) vfunc, hook_fn );
		VirtualProtectEx( csgo, ( void* ) vfunc, sizeof( void* ), old_protect, &old_protect );
		return o_vfunc;
	}

	MODULEENTRY32 get_module_by_name( const char* module_name ) {
		MODULEENTRY32 entry = { 0 };
		void* snap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid );

		if ( !snap )
			return { 0 };

		entry.dwSize = sizeof( entry );
		bool run_module = Module32First( snap, &entry );

		while ( run_module ) {
			if ( !strcmp( ( char* ) entry.szModule, module_name ) ) {
				CloseHandle( snap );
				return entry;
			}

			run_module = Module32Next( snap, &entry );
		}

		CloseHandle( snap );

		return { 0 };
	}

	bool compare_byte( const byte* data, const byte* sig, const char* mask ) {
		for ( ; *mask; ++mask, ++data, ++sig ) {
			if ( *mask == 'x' && *data != *sig )
				return false;
		}

		return ( *mask == 0 );
	}

	void* find_pattern( const char* module_name, const char* sig, const char* mask ) {
		auto module32 = strstr( module_name, "client.dll" ) ? client_dll : engine_dll;
		byte* data = new byte[ module32.modBaseSize ];
		ReadProcessMemory( csgo, ( void* ) ( module32.modBaseAddr ), data, module32.modBaseSize, nullptr );

		for ( uintptr_t i { }; i < module32.modBaseSize; i++ ) {
			if ( compare_byte( ( const byte* ) ( data + i ), ( const byte* ) sig, mask ) ) {
				delete[ ] data;
				return ( void* ) ( ( uintptr_t ) module32.modBaseAddr + i );
			}
		}

		return nullptr;
	}

	void* hook_detour( void* src, void* dst, size_t len ) {
		if ( len < 5 )
			return nullptr;

		unsigned long old_protection;
		VirtualProtectEx( csgo, src, len, PAGE_EXECUTE_READWRITE, &old_protection );
		void* trampoline = VirtualAllocEx( csgo, nullptr, len + 0x5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

		for ( int i = 0; i < len; i++ ) {
			write< byte >( ( uintptr_t ) trampoline + i, read< byte >( ( uintptr_t ) src + i ) );
			write< byte >( ( uintptr_t ) src + i, 0x90 );
		}

		write< byte >( ( uintptr_t ) trampoline + len, 0xE9 );
		write< uintptr_t >( ( uintptr_t ) trampoline + len + 0x1, ( ( ( uintptr_t ) src + len ) - ( ( uintptr_t ) trampoline + len ) ) - 0x5 );

		write< byte >( ( uintptr_t ) src, 0xE9 );
		write< uintptr_t >( ( uintptr_t ) src + 0x1, ( ( uintptr_t ) dst - ( uintptr_t ) src ) - 0x5 );
		VirtualProtectEx( csgo, src, len, old_protection, &old_protection );

		return trampoline;
	}
};

extern std::unique_ptr< c_memory > memory;