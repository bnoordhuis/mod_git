mod_git.la: mod_git.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_git.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_git.la
