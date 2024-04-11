deps = [ ]

sources = [
	'cxlmi/log.c',
	'cxlmi/cxlmi.c'
]

cxlmi = library('cxlmi', # defaults to shared lib
		sources,
		include_directories : inc,
		dependencies : deps,
		install : true)

libcxlmi_dep = declare_dependency(
    include_directories: ['.'],
    link_with: cxlmi,
)
