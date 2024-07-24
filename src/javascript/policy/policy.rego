package main

import future.keywords.in
import future.keywords.if

allow_list := { "npm ci", "npm ci --omit=dev", "apt update", "apt upgrade -y" }
trusted_repo := [ "docker.io/library/", "library/", "ghcr.io/chukmunnlee/" ]

# Cannot use :latest tag 
deny_image_latest_tag[msg] {
	some i
		input[i].Cmd = "from"
		img := split(input[i].Value[0], ":")
		count(img) > 1
		img[1] == ":latest" 
		msg := sprintf("Cannot use 'latest' in image: %s", [ input[i].Value[0] ])
}

# Must specify image tag 
deny_image_no_tag[msg] {
	some i
		input[i].Cmd = "from"
		img := split(input[i].Value[0], ":")
		count(img) = 1
		msg := sprintf("Must use RepoDigest (@sha256:) instead of image tag: %s", [ input[i].Value[0] ])
}

# Must use repository digest to identify image
deny_image_non_repodigest_tag[msg] {
	some i
		input[i].Cmd = "from"
		img := split(input[i].Value[0], "@")
		count(img) = 1
		msg := sprintf("Must use RepoDigest (@sha256:) to identify image: %s", [ input[i].Value[0] ])
}

# Ignore the tag rules if the image is from a trusted repository
exception[rules] {
	some i
		input[i].Cmd = "from"
		trusted = [ 1 | startswith(input[i].Value[0],  trusted_repo[_]) ]
		count(trusted) > 0
		rules := [ "image_latest_tag", "image_no_tag", "image_non_repodigest_tag" ]
}

# Can only run commands in allow_list 
deny[msg] {
	some i
		input[i].Cmd = "run"
		cmd := regex.split("\\&\\& | \\|\\|", input[i].Value[0])
		s_cmd = { trim_space(c) | c := cmd[_] }
		count(s_cmd - allow_list) > 0
		msg := sprintf("Cannot RUN the following: %s", [ cmd ])
}

# Must not run as root
deny[msg] {
	user := [ user | input[i].Cmd == "user"; user = input[i].Value[0] ]
	count(user) <= 0
	msg := sprintf("Cannot run as root", [])
}

deny[msg] {
	user := [ to_number(user) | input[i].Cmd == "user"; user = input[i].Value[0] ]
	user[0] < 1000
	msg := sprintf("Cannot run as root: %s", [user])
}

should_include_command(directive) = true if count([ 1 | input[i].Cmd == directive ]) <= 0

# Label the image
warn[msg] {
	#count([label | input[i].Cmd == "label"; label = input[i].Value ]) <= 0
	should_include_command("label")
	msg := sprintf("Label the image", [])
}

# Include HEALTHCHECK
warn[msg] {
	should_include_command("healthcheck")
	msg := sprintf("Add a healthcheck to your image", [])
}

# Use ENTRYPOINT to start the container
warn[msg] {
	input[i].Cmd == "cmd"
	should_include_command("entrypoint")
	not should_include_command("cmd")
	msg := sprintf("Prefer ENTRYPOINT over CMD: %s", [ input[i].Value ])
}
