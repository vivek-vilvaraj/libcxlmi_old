mi_deps = [ ]

cxlmi_sources = ['cxlmi.c']
cxlmi = library('cxlmi',
		cxlmi_sources,
		include_directories : inc,
		dependencies : mi_deps,
		install : true)

libcxlmi_dep = declare_dependency(
    include_directories: ['.'],
    link_with: cxlmi,
)
