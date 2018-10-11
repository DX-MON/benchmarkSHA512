project(
	'sha512 benchmarking',
	'cpp',
	default_options: [
		'cpp_std=c++14',
		'warning_level=3',
		'buildtype=release'
	],
	version: '0.1.0'
)

compiler = meson.get_compiler('cpp')
googleBenchmark = dependency('benchmark')
clock = compiler.find_library('rt', required: false)
threads = dependency('threads')

#openSSL = dependency('openssl', version: '>=1.1.0')
openSSL = dependency('openssl', version: '>=1.0.2')

sha512_src = [
	'sha512.cxx',
	'benchmarkSHA512.cxx'
]

benchmark = executable(
	'benchmarkSHA512',
	sha512_src,
	dependencies: [googleBenchmark, clock, threads, openSSL],
	build_by_default: true
)
