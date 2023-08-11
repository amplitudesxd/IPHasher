#ifndef BOTAN_BUILD_CONFIG_H_
#define BOTAN_BUILD_CONFIG_H_

/**
* @file  build.h
* @brief Build configuration for Botan 3.2.0
*
* Automatically generated from
* 'configure.py --disable-modules=pkcs11,aes,tls12,tls13,rsa,ecdsa,argon2,chacha,pubkey,salsa20,sodium,socket,stream,x509,adler32,aead,aria,asn1,bcrypt,bcrypt_pbkdf,blake2,blake2mac,blowfish,camellia,cbc,ccm,cfb,cmac,comb4p,crc24,crc32,des,pbldf,pbkdf2,pgp_s2k,poly1305,poly_dbl,siphash,twofish,tss,whirlpool,xts,zfec,streebog,skein,serpent,treefish_512,shake,sm3,sm4,md5,md4,mac,hmac,win32_stats,uuid,threefish_512,ghash'
*
* Target
*  - Compiler: cl  /std:c++20 /EHs /GR /MD /bigobj /O2 /Oi
*  - Arch: x86_64
*  - OS: windows
*/

/**
 * @defgroup buildinfo Build Information
 */

/**
 * @ingroup buildinfo
 * @defgroup buildinfo_version Build version information
 * @{
 */

#define BOTAN_VERSION_MAJOR 3
#define BOTAN_VERSION_MINOR 2
#define BOTAN_VERSION_PATCH 0
#define BOTAN_VERSION_DATESTAMP 0


#define BOTAN_VERSION_RELEASE_TYPE "unreleased"

#define BOTAN_VERSION_VC_REVISION "git:8c72bab4c7e2348beb6753b8df9c3e9a65f89594"

#define BOTAN_DISTRIBUTION_INFO "unspecified"

/**
 * @}
 */

/**
 * @ingroup buildinfo
 * @defgroup buildinfo_configuration Build configurations
 * @{
 */

/** How many bits per limb in a BigInt */
#define BOTAN_MP_WORD_BITS 64


#define BOTAN_INSTALL_PREFIX R"(c:\Botan)"
#define BOTAN_INSTALL_HEADER_DIR R"(include/botan-3)"
#define BOTAN_INSTALL_LIB_DIR R"(c:\Botan\lib)"
#define BOTAN_LIB_LINK ""
#define BOTAN_LINK_FLAGS ""


#ifndef BOTAN_DLL
  #define BOTAN_DLL __declspec(dllimport)
#endif

/* Target identification and feature test macros */

#define BOTAN_TARGET_OS_IS_WINDOWS

#define BOTAN_TARGET_OS_HAS_ATOMICS
#define BOTAN_TARGET_OS_HAS_CERTIFICATE_STORE
#define BOTAN_TARGET_OS_HAS_FILESYSTEM
#define BOTAN_TARGET_OS_HAS_RTLGENRANDOM
#define BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY
#define BOTAN_TARGET_OS_HAS_THREAD_LOCAL
#define BOTAN_TARGET_OS_HAS_THREADS
#define BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
#define BOTAN_TARGET_OS_HAS_WIN32
#define BOTAN_TARGET_OS_HAS_WINSOCK2


#define BOTAN_BUILD_COMPILER_IS_MSVC




#define BOTAN_TARGET_ARCH "x86_64"
#define BOTAN_TARGET_ARCH_IS_X86_64
#define BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN
#define BOTAN_TARGET_CPU_IS_X86_FAMILY
#define BOTAN_TARGET_CPU_HAS_NATIVE_64BIT

#define BOTAN_TARGET_SUPPORTS_AESNI
#define BOTAN_TARGET_SUPPORTS_AVX2
#define BOTAN_TARGET_SUPPORTS_AVX512
#define BOTAN_TARGET_SUPPORTS_RDRAND
#define BOTAN_TARGET_SUPPORTS_RDSEED
#define BOTAN_TARGET_SUPPORTS_SHA
#define BOTAN_TARGET_SUPPORTS_SSE2
#define BOTAN_TARGET_SUPPORTS_SSE41
#define BOTAN_TARGET_SUPPORTS_SSE42
#define BOTAN_TARGET_SUPPORTS_SSSE3






/**
 * @}
 */

/**
 * @ingroup buildinfo
 * @defgroup buildinfo_modules Enabled modules and API versions
 * @{
 */

/*
* Module availability definitions
*/
#define BOTAN_HAS_BASE32_CODEC 20180418
#define BOTAN_HAS_BASE58_CODEC 20181209
#define BOTAN_HAS_BASE64_CODEC 20131128
#define BOTAN_HAS_BIGINT 20210423
#define BOTAN_HAS_BIGINT_MP 20151225
#define BOTAN_HAS_BLOCK_CIPHER 20131128
#define BOTAN_HAS_CASCADE 20131128
#define BOTAN_HAS_CAST 20131128
#define BOTAN_HAS_CAST_128 20171203
#define BOTAN_HAS_CIPHER_MODES 20180124
#define BOTAN_HAS_CIPHER_MODE_PADDING 20131128
#define BOTAN_HAS_CODEC_FILTERS 20131128
#define BOTAN_HAS_CPUID 20170917
#define BOTAN_HAS_DYNAMIC_LOADER 20160310
#define BOTAN_HAS_EME_OAEP 20180305
#define BOTAN_HAS_EME_PKCS1 20190426
#define BOTAN_HAS_EME_PKCS1v15 20131128
#define BOTAN_HAS_EME_RAW 20150313
#define BOTAN_HAS_EMSA_PKCS1 20140118
#define BOTAN_HAS_EMSA_PSSR 20131128
#define BOTAN_HAS_EMSA_RAW 20131128
#define BOTAN_HAS_EMSA_X931 20140118
#define BOTAN_HAS_ENTROPY_SOURCE 20151120
#define BOTAN_HAS_ENTROPY_SRC_RDSEED 20151218
#define BOTAN_HAS_FILTERS 20160415
#define BOTAN_HAS_GOST_28147_89 20131128
#define BOTAN_HAS_GOST_34_11 20131128
#define BOTAN_HAS_HASH 20180112
#define BOTAN_HAS_HASH_ID 20131128
#define BOTAN_HAS_HEX_CODEC 20131128
#define BOTAN_HAS_IDEA 20131128
#define BOTAN_HAS_IDEA_SSE2 20131128
#define BOTAN_HAS_ISO_9796 20161121
#define BOTAN_HAS_KECCAK 20131128
#define BOTAN_HAS_LOCKING_ALLOCATOR 20131128
#define BOTAN_HAS_MDX_HASH_FUNCTION 20131128
#define BOTAN_HAS_MEM_POOL 20180309
#define BOTAN_HAS_MGF1 20140118
#define BOTAN_HAS_MODES 20150626
#define BOTAN_HAS_NIST_KEYWRAP 20171119
#define BOTAN_HAS_NOEKEON 20131128
#define BOTAN_HAS_NOEKEON_SIMD 20160903
#define BOTAN_HAS_NUMBERTHEORY 20201108
#define BOTAN_HAS_PARALLEL_HASH 20131128
#define BOTAN_HAS_PK_PADDING 20131128
#define BOTAN_HAS_PROCESSOR_RNG 20200508
#define BOTAN_HAS_RAW_HASH_FN 20230221
#define BOTAN_HAS_RIPEMD_160 20131128
#define BOTAN_HAS_SEED 20131128
#define BOTAN_HAS_SHA1 20131128
#define BOTAN_HAS_SHA1_SSE2 20160803
#define BOTAN_HAS_SHA1_X86_SHA_NI 20170518
#define BOTAN_HAS_SHA2_32 20131128
#define BOTAN_HAS_SHA2_32_X86 20170518
#define BOTAN_HAS_SHA2_64 20131128
#define BOTAN_HAS_SHA3 20161018
#define BOTAN_HAS_SHACAL2 20170813
#define BOTAN_HAS_SHACAL2_AVX2 20180826
#define BOTAN_HAS_SHACAL2_SIMD 20170813
#define BOTAN_HAS_SHACAL2_X86 20170814
#define BOTAN_HAS_SIMD_32 20131128
#define BOTAN_HAS_SIMD_AVX2 20180824
#define BOTAN_HAS_SIMD_AVX512 20230101
#define BOTAN_HAS_STATEFUL_RNG 20160819
#define BOTAN_HAS_SYSTEM_RNG 20141202
#define BOTAN_HAS_THREAD_UTILS 20190922
#define BOTAN_HAS_TRUNCATED_HASH 20230215
#define BOTAN_HAS_UTIL_FUNCTIONS 20180903


/**
 * @}
 */

/**
 * @addtogroup buildinfo_configuration
 * @{
 */

/** Local/misc configuration options (if any) follow */


/*
* Things you can edit (but probably shouldn't)
*/

/** How much to allocate for a buffer of no particular size */
#define BOTAN_DEFAULT_BUFFER_SIZE 4096

#if defined(BOTAN_HAS_VALGRIND) || defined(BOTAN_ENABLE_DEBUG_ASSERTS)
   /**
    * @brief Prohibits access to unused memory pages in Botan's memory pool
    *
    * If BOTAN_MEM_POOL_USE_MMU_PROTECTIONS is defined, the Memory_Pool
    * class used for mlock'ed memory will use OS calls to set page
    * permissions so as to prohibit access to pages on the free list, then
    * enable read/write access when the page is set to be used. This will
    * turn (some) use after free bugs into a crash.
    *
    * The additional syscalls have a substantial performance impact, which
    * is why this option is not enabled by default. It is used when built for
    * running in valgrind or debug assertions are enabled.
    */
   #define BOTAN_MEM_POOL_USE_MMU_PROTECTIONS
#endif

/**
* If enabled uses memset via volatile function pointer to zero memory,
* otherwise does a byte at a time write via a volatile pointer.
*/
#define BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO 1

/**
* Normally blinding is performed by choosing a random starting point (plus
* its inverse, of a form appropriate to the algorithm being blinded), and
* then choosing new blinding operands by successive squaring of both
* values. This is much faster than computing a new starting point but
* introduces some possible corelation
*
* To avoid possible leakage problems in long-running processes, the blinder
* periodically reinitializes the sequence. This value specifies how often
* a new sequence should be started.
*/
#define BOTAN_BLINDING_REINIT_INTERVAL 64

/**
* Userspace RNGs like HMAC_DRBG will reseed after a specified number
* of outputs are generated. Set to zero to disable automatic reseeding.
*/
#define BOTAN_RNG_DEFAULT_RESEED_INTERVAL 1024

/** Number of entropy bits polled for reseeding userspace RNGs like HMAC_DRBG */
#define BOTAN_RNG_RESEED_POLL_BITS 256

#define BOTAN_RNG_RESEED_DEFAULT_TIMEOUT std::chrono::milliseconds(50)

/**
* Specifies (in order) the list of entropy sources that will be used
* to seed an in-memory RNG.
*/
#define BOTAN_ENTROPY_DEFAULT_SOURCES \
   { "rdseed", "hwrng", "getentropy", "system_rng", "system_stats" }

/** Multiplier on a block cipher's native parallelism */
#define BOTAN_BLOCK_CIPHER_PAR_MULT 4

/* Check for a common build problem */

#if defined(BOTAN_TARGET_ARCH_IS_X86_64) && ((defined(_MSC_VER) && !defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__x86_64__)) || \
                                             (defined(__GNUG__) && !defined(__x86_64__)))
    #error "Trying to compile Botan configured as x86_64 with non-x86_64 compiler."
#endif

#if defined(BOTAN_TARGET_ARCH_IS_X86_32) && ((defined(_MSC_VER) && defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__i386__)) || \
                                             (defined(__GNUG__) && !defined(__i386__)))

    #error "Trying to compile Botan configured as x86_32 with non-x86_32 compiler."
#endif

#endif
