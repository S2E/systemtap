// systemtap compile-server server backends.
// Copyright (C) 2017 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "backends.h"
#include <iostream>
#include <fstream>
#include "../util.h"
#include "utils.h"

extern "C" {
#include <string.h>
#include <glob.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
}

using namespace std;


class default_backend : public backend_base
{
public:
    
    bool can_generate_module(const client_request_data *) {
	return true;
    }
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &tmp_dir,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);
};

int
default_backend::generate_module(const client_request_data *crd,
				 const vector<string> &,
				 const string &,
				 const string &,
				 const string &stdout_path,
				 const string &stderr_path)
{
    ofstream stdout_stream, stderr_stream;

    // Create an empty stdout file.
    stdout_stream.open(stdout_path);
    if (stdout_stream.is_open()) {
	stdout_stream.close();
    }

    // Create an stderr file with an error message.
    stderr_stream.open(stderr_path);
    if (stderr_stream.is_open()) {
	stderr_stream << "Error: the server cannot create a module for kernel "
		      << crd->kver << ", architecture " << crd->arch
		      << ", distro " << crd->distro_name << endl;
	stderr_stream.close();
    }
    return 1;
}


class local_backend : public backend_base
{
public:
    local_backend();

    bool can_generate_module(const client_request_data *crd);
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &tmp_dir,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);

private:
    // <kernel version, build tree path>
    map<string, string> supported_kernels;

    string distro_name;

    // The current architecture.
    string arch;
};


local_backend::local_backend()
{
    glob_t globber;
    string pattern = "/lib/modules/*/build";
    int rc = glob(pattern.c_str(), GLOB_ERR, NULL, &globber);

    if (rc) {
	// We weren't able to find any kernel build trees. This isn't
	// a fatal error, since one of the other backends might be
	// able to satisfy requests.
	//
	// FIXME: By reading the directory here, we'll only see
	// kernel build trees installed at startup. If a kernel build
	// tree gets installed after startup, we won't see it.
	return;
    }
    for (unsigned int i = 0; i < globber.gl_pathc; i++) {
	string path = globber.gl_pathv[i];

	supported_kernels.insert({kernel_release_from_build_tree(path), path});
    }
    globfree(&globber);

    // Notice we don't error if we can't get the distro name. This
    // isn't a fatal error, since other backends might be able to
    // handle this request.
    vector<string> info;
    get_distro_info(info);
    if (! info.empty()) {
	distro_name = info[0];
	transform(distro_name.begin(), distro_name.end(), distro_name.begin(), ::tolower);
    }

    // Get the current arch name.
    struct utsname buf;
    (void)uname(&buf);
    arch = buf.machine;
}

bool
local_backend::can_generate_module(const client_request_data *crd)
{
    // See if we support the kernel/arch/distro combination.
    if (supported_kernels.count(crd->kver) == 1 && arch == crd->arch
	&& distro_name == crd->distro_name) {
	return true;
    }

    return false;
}

int
local_backend::generate_module(const client_request_data *crd,
			       const vector<string> &argv,
			       const string &,
			       const string &,
			       const string &stdout_path,
			       const string &stderr_path)
{
    // Make sure we're running the correct version of systemtap.
    vector<string> cmd = argv;
    cmd[0] = string(BINDIR) + "/stap";
    return execute_and_capture(2, cmd, crd->env_vars,
			       stdout_path, stderr_path);
}


class docker_backend : public backend_base
{
public:
    docker_backend();

    bool can_generate_module(const struct client_request_data *crd);
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &tmp_dir,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);

private:
    // The docker executable path.
    string docker_path;

    // The docker data directory.
    string datadir;
    
    // List of docker data filenames. <distro name, path>
    map<string, string> data_files;

    // The current architecture.
    string arch;

    // The script path that builds a docker container.
    string docker_build_container_script_path;
};


docker_backend::docker_backend()
{
    try {
	docker_path = find_executable("docker");
	// If find_executable() can't find the path, it returns the
	// name you passed it.
	if (docker_path == "docker")
	    docker_path.clear();
    }
    catch (...) {
	// It really isn't an error for the system to not have the
	// "docker" executable. We'll just disallow builds using the
	// docker backend (down in
	// docker_backend::can_generate_module()).
	docker_path.clear();
    }
    
    docker_build_container_script_path = string(PKGLIBDIR)
	+ "/httpd/docker/stap_build_docker_image.py";

    datadir = string(PKGDATADIR) + "/httpd/docker";

    glob_t globber;
    string pattern = datadir + "/*.json";
    int rc = glob(pattern.c_str(), GLOB_ERR, NULL, &globber);
    if (rc) {
	// We weren't able to find any JSON docker data files. This
	// isn't a fatal error, since one of the other backends might
	// be able to satisfy requests.
	//
	// FIXME: By reading the directory here, we'll only see distro
	// json files installed at startup. If one gets installed
	// after startup, we won't see it.
	return;
    }
    for (unsigned int i = 0; i < globber.gl_pathc; i++) {
	string path = globber.gl_pathv[i];
	
	size_t found = path.find_last_of("/");
	if (found != string::npos) {
	    // First, get the file basename ("FOO.json").
	    string filename = path.substr(found + 1);

	    // Now, chop off the .json extension.
	    size_t found = filename.find_last_of(".");
	    if (found != string::npos) {
		// Notice we're lowercasing the distro name to make
		// things simpler.
		string distro = filename.substr(0, found);
		transform(distro.begin(), distro.end(), distro.begin(),
			  ::tolower);
		data_files.insert({distro, path});
	    }
	}
    }
    globfree(&globber);

    // Get the current arch name.
    struct utsname buf;
    (void)uname(&buf);
    arch = buf.machine;
}

bool
docker_backend::can_generate_module(const client_request_data *crd)
{
    // If we don't have a docker executable, we're done.
    if (docker_path.empty())
	return false;

    // We have to see if we have a JSON data file for that distro and
    // the arches match.
    if (data_files.count(crd->distro_name) == 1 && arch == crd->arch) {
	return true;
    }

    return false;
}

int
docker_backend::generate_module(const client_request_data *crd,
				const vector<string> &argv,
				const string &tmp_dir,
				const string &uuid,
				const string &stdout_path,
				const string &stderr_path)
{
    vector<string> images_to_remove;
    vector<string> containers_to_remove;

    // Handle capturing docker's stdout and stderr (along with using
    // /dev/null for stdin). If the client requested it, just use
    // stap's stdout/stderr files.
    string docker_stdout_path, docker_stderr_path;
    if (crd->verbose >= 3) {
	docker_stdout_path = stdout_path;
	docker_stderr_path = stderr_path;
    }
    else {
	docker_stdout_path = tmp_dir + "/docker_stdout";
	docker_stderr_path = tmp_dir + "/docker_stderr";
    }

    // Grab a JSON representation of the client_request_data, and
    // write it to a file (so the script that generates the docker
    // file(s) knows what it is supposed to be doing).
    string build_data_path = string(tmp_dir) + "/build_data.json";
    struct json_object *root = crd->get_json_object();
    server_error(_F("JSON data: %s", json_object_to_json_string(root)));
    ofstream build_data_file;
    build_data_file.open(build_data_path, ios::out);
    build_data_file << json_object_to_json_string(root);
    build_data_file.close();
    json_object_put(root);

    string stap_image_uuid = uuid;

    // Kick off building the docker image. Note we're using the UUID
    // as the docker image name. This keeps us from trying to build
    // multiple images with the same name at the same time.
    vector<string> docker_args;
#if defined(PYTHON3_BASENAME)
    docker_args.push_back(PYTHON3_BASENAME);
#elif defined(PYTHON_BASENAME)
    docker_args.push_back(PYTHON_BASENAME);
#else
#error "Couldn't find python version 2 or 3."
#endif
    docker_args.push_back(docker_build_container_script_path);
    docker_args.push_back("--distro-file");
    docker_args.push_back(data_files[crd->distro_name]);
    docker_args.push_back("--build-file");
    docker_args.push_back(build_data_path);
    docker_args.push_back("--data-dir");
    docker_args.push_back(datadir);
    docker_args.push_back(stap_image_uuid);

    int rc = execute_and_capture(2, docker_args, crd->env_vars,
				 docker_stdout_path, docker_stderr_path);
    server_error(_F("Spawned process returned %d", rc));
    if (rc != 0) {
	server_error(_F("%s failed.",
			docker_build_container_script_path.c_str()));
	return -1;
    }

    // The client can optionally send over a "client.zip" file, which
    // was unziped up in build_info::module_build(). If it exists, we
    // need to copy those files down into the container image before
    // we run stap.
    for (auto i = crd->files.begin(); i != crd->files.end(); i++) {
	if (*i == "client.zip") {
	    // First, create a docker file.
	    string docker_file_path = crd->base_dir + "/files.docker";
	    ofstream docker_file;
	    docker_file.open(docker_file_path, ios::out);
	    docker_file << "FROM " << stap_image_uuid << endl;
	    docker_file << "MAINTAINER http://sourceware.org/systemtap/"
			<< endl;
	    docker_file << "COPY . " << tmp_dir << "/" << endl;
	    docker_file.close();
	    // Grab another uuid.
	    stap_image_uuid = get_uuid();

	    // Now run "docker build" with that docker file.
	    docker_args.clear();
	    docker_args.push_back("docker");
	    docker_args.push_back("build");
	    docker_args.push_back("-t");
	    docker_args.push_back(stap_image_uuid);
	    docker_args.push_back("-f");
	    docker_args.push_back(docker_file_path);
	    docker_args.push_back(crd->base_dir);

	    rc = execute_and_capture(2, docker_args, crd->env_vars,
				     docker_stdout_path, docker_stderr_path);
	    server_error(_F("Spawned process returned %d", rc));
	    if (rc != 0) {
		server_error("docker build failed.");
		return -1;
	    }

	    // We want to remove the image that we just built.
	    images_to_remove.push_back(stap_image_uuid);
	    break;
	}
    }

    // Create a temporary directory to use.
    string sysroot_dir = tmp_dir + "/sysroot";
    rc = mkdir(sysroot_dir.c_str(), 0700);

    // Mount the docker image to the temporary directory.
    if (rc == 0) {
	docker_args.clear();
	docker_args.push_back("atomic");
	docker_args.push_back("mount");
	docker_args.push_back(stap_image_uuid);
	docker_args.push_back(sysroot_dir);
	rc = execute_and_capture(2, docker_args, crd->env_vars,
				 docker_stdout_path, docker_stderr_path);
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("atomic mount failed.");
	    // We can't return here, we've got to clean up.
	}
    }

    // Run stap, using the mounted docker image as the sysroot.
    int saved_rc = rc;
    if (rc == 0) {
	docker_args.clear();
	for (auto it = argv.begin(); it != argv.end(); it++) {
	    docker_args.push_back(*it);
	}

	// Make sure we're running the correct version of systemtap.
	docker_args[0] = string(BINDIR) + "/stap";

	// Insert our sysroot option into the stap command line.
	string sysroot_option = "--sysroot=" + sysroot_dir;
	docker_args.insert(docker_args.begin() + 1, sysroot_option);
	saved_rc = execute_and_capture(2, docker_args, crd->env_vars,
				       stdout_path, stderr_path);
	server_error(_F("Spawned process returned %d", saved_rc));
	if (saved_rc != 0) {
	    server_error("stap failed.");
	    // We can't return here, we've got to clean up.
	}
    }

    // Unmount the docker image.
    if (rc == 0) {
	docker_args.clear();
	docker_args.push_back("atomic");
	docker_args.push_back("unmount");
	docker_args.push_back(sysroot_dir);
	rc = execute_and_capture(2, docker_args, crd->env_vars,
				 docker_stdout_path, docker_stderr_path);
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("atomic unmount failed.");
	    // We can't return here, we still need to clean up.
	}
    }

    // OK, at this point we've created a container, run stap, and
    // copied out any result. Let's do a little cleanup and delete the
    // last layer. We'll leave (for now) the container with all the
    // files, but delete the layer that got created as stap was run
    // (since there is no reuse there).
    //
    // docker rm/rmi stap_container_uuid
    //
    // Note that we have to remove the containers first, because they
    // depend on the images.

    // FIXME: MORE CLEANUP NEEDED!
    //
    // Note that we're not removing the initial docker image we built,
    // so if the user turns right around again and builds another
    // script that image will get reused. But, that initial docker
    // image never gets deleted currently. The "docker images" command
    // knows when an image was created, but not the last time it was
    // used.
    //
    // We might be able to tie in the information from "docker ps -a",
    // which lists all containers, and when they were created. Since
    // the containers are short-lived (they just exist to run "stap"),
    // their creation date is really the last used date of the related
    // image. But, of course we delete that container at the end of
    // every run so that info gets deleted. In theory we could leave
    // that container around and every so often run a python script
    // that puts the two bits of information together and deletes
    // images and containers that haven't been used in a while.

    if (! containers_to_remove.empty()) {
	docker_args.clear();
	docker_args.push_back("docker");
	docker_args.push_back("rm");
	for (auto i = containers_to_remove.begin();
	     i != containers_to_remove.end(); i++) {
	    docker_args.push_back(*i);
	}
	rc = execute_and_capture(2, docker_args, crd->env_vars,
				 docker_stdout_path, docker_stderr_path);
	// Note that we're ignoring any errors here.
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("docker rm failed.");
	}
    }
    if (! images_to_remove.empty()) {
	docker_args.clear();
	docker_args.push_back("docker");
	docker_args.push_back("rmi");
	for (auto i = images_to_remove.begin(); i != images_to_remove.end();
	     i++) {
	    docker_args.push_back(*i);
	}
	rc = execute_and_capture(2, docker_args, crd->env_vars,
				 docker_stdout_path, docker_stderr_path);
	// Note that we're ignoring any errors here.
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("docker rmi failed.");
	}
    }
    return saved_rc;
}

static vector<backend_base *>saved_backends;
static void backends_atexit_handler()
{
    if (!saved_backends.empty()) {
	for (auto it = saved_backends.begin(); it != saved_backends.end();
	     it++) {
	    delete *it;
	}
	saved_backends.clear();
    }
}

void
get_backends(vector<backend_base *> &backends)
{
    std::atexit(backends_atexit_handler);
    if (saved_backends.empty()) {
	// Note that order *is* important here. We want to try the
	// local backend first (since it would be the fastest), then
	// the docker backend, and finally the default backend (which
	// just returns an error).
	saved_backends.push_back(new local_backend());
	saved_backends.push_back(new docker_backend());
	saved_backends.push_back(new default_backend());
    }
    backends.clear();
    backends = saved_backends;
}
