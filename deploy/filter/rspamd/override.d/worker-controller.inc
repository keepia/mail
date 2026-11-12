# Keepia Mail, filter role (#5 plan, "Compose template"): the controller
# listens on loopback only. The image's rspamd.conf binds every worker on
# RSPAMD_LOCAL_ADDR, which the Compose file sets to the container's private
# address for the normal and proxy workers; override.d wins over that
# (priority 10). Nothing outside the container reaches the controller.
bind_socket = "172.29.7.10:11334";
