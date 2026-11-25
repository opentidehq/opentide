# prod:block_comment valid
/* Search for killed processes */ ?{signal="*"} | /Service exited due to (?<signal>\S+)/ | signal = ?signal
