# !/usr/bin/python
""" Module that wraps docker to remove the docker-py dependency """

from subp import subp
import json


class DockerError(Exception):
    """ Generic error for shelling to docker. """

    def __init__(self, val):
        self.val = val

    def __str__(self):
        return str(self.val)


class docker:

    def __init__(self):
        cmd = ['docker', '-v']
        r = subp(cmd)
        if r.return_code != 0:
            raise Exception('Unable to communicate with the docker server')

    def inspect(self, obj_id):
        # returns dict representation of "docker inspect ID"
        cmd = ['docker', 'inspect', obj_id]
        r = subp(cmd)
        if r.return_code != 0:
            raise Exception('Unable to inspect object: %s' % obj_id)
        return json.loads(r.stdout)[0]

    def driver(self):
        # returns the storage driver docker is using
        cmd = ['docker', 'info']
        r = subp(cmd)
        if r.return_code != 0:
            raise Exception('Unable to get docker info')

        for line in r.stdout.strip().split('\n'):
            if line.startswith('Storage Driver'):
                pre, _, post = line.partition(':')
                return post.strip()
        raise Exception('Unable to get docker storage driver')

    def dm_pool(self):
        # ONLY FOR DEVICEMAPPER
        # returns the docker-pool docker is using
        cmd = ['docker', 'info']
        r = subp(cmd)
        if r.return_code != 0:
            raise Exception('Unable to get docker info')
        for line in r.stdout.strip().split('\n'):
            if line.strip().startswith('Pool Name'):
                pre, _, post = line.partition(':')
                return post.strip()
        raise Exception('Unable to get docker pool name')

    def images(self, all=False, quiet=False):
        # returns a list of dicts, each dict is an image's information
        # except when quiet is used - which returns a list of image ids
        # dict keys:
            # Created
            # Labels
            # VirtualSize
            # ParentId
            # RepoTags
            # RepoDigests
            # Id
            # Size
        # Adding --no-trunc to ensure we get full ID's if any quiet is True
        cmd = ['docker', 'images', '-q', '--no-trunc']
        if all:
            cmd.append("-a")
        r = subp(cmd)
        if r.return_code != 0:
            raise Exception('Unable to get docker images')
        images = r.stdout.strip().split('\n')
        if quiet:
            return images
        else:
            ims = []
            for i in images:
                inspec = self.inspect(i)
                dic = {}
                dic['Created'] = inspec['Created']
                if inspec['Config']:
                    dic['Labels'] = inspec['Config']['Labels']
                else:
                    dic['Labels'] = {}
                dic['VirtualSize'] = inspec['VirtualSize']
                dic['ParentId'] = inspec['Parent']
                dic['RepoTags'] = inspec['RepoTags']
                dic['RepoDigests'] = inspec['RepoDigests']
                dic['Id'] = inspec['Id']
                dic['Size'] = inspec['Size']
                ims.append(dic)
            return ims

    def containers(self, all=False, quiet=False):
        # returns a list of dicts, each dict is an containers's information
        # except when quiet is used - which returns a list of container ids
        # dict keys:
            # Status
            # Created
            # Image
            # Labels
            # NetworkSettings
            # HostConfig
            # ImageID
            # Command
            # Names
            # Id
            # Ports
        cmd = ['docker', 'ps', '-q']
        if all:
            cmd.append("-a")
        r = subp(cmd)
        if r.return_code != 0:
            raise Exception('Unable to get docker containers')
        containers = r.stdout.strip().split('\n')
        if quiet:
            return containers
        else:
            conts = []
            for i in containers:
                inspec = self.inspect(i)
                dic = {}
                dic['Status'] = inspec['State']['Status']
                dic['Created'] = inspec['Created']
                dic['Image'] = inspec['Config']['Image']
                dic['Labels'] = inspec['Config']['Labels']
                dic['NetworkSettings'] = inspec['NetworkSettings']
                dic['HostConfig'] = inspec['HostConfig']
                dic['ImageID'] = inspec['Image']
                dic['Command'] = inspec['Config']['Cmd']
                dic['Names'] = inspec['Name']
                dic['Id'] = inspec['Id']
                dic['Ports'] = inspec['NetworkSettings']['Ports']
                conts.append(dic)
            return conts

    def remove_container(self, cid):
        # removes container cid
        cmd = ['docker', 'rm', cid]
        r = subp(cmd)
        if r.return_code != 0:
            raise DockerError('Unable to remove docker container %s' % cid)

    def remove_image(self, iid, noprune=False):
        # removes image iid
        cmd = ['docker', 'rmi', iid]
        if noprune:
            cmd.append('--no-prune')
        r = subp(cmd)
        if r.return_code != 0:
            raise DockerError('Unable to remove docker image %s' % iid)

    def create_container(self, image, command, environment, detach, network_disabled):
        # Note: There is no 'docker run' in the docker-pyhton api, it uses a derivative of
        # 'docker create' and 'docker run' - we can use 'docker run' to create what we need
        cmd = ['docker', 'run']

        if len(environment) > 0:
            for env in environment:
                cmd.append('-e')
                cmd.append(env)

        if detach:
            cmd.append('-d')

        # MAKE SURE THIS SHIT WORKS IN LATER DOCKER VERSIONS (MAY HAVE CHANGED TO --network)
        if network_disabled:
            cmd.append('--net=none')

        cmd.append(image)
        cmd.append(command)

        r = subp(cmd)
        if r.return_code != 0:
            raise DockerError('Unable to create docker image %s' % image)

        # return the id of the new container
        return r.stdout.strip()

    def commit(self, cid):
        cmd = ['docker', 'commit']

        cmd.append('-c')
        cmd.append('LABEL \'io.projectatomic.Temporary\': \'true\'')
        cmd.append(cid)

        r = subp(cmd)
        if r.return_code != 0:
            raise DockerError('Unable to commit docker container %s' % cid)

        # return newly created image id
        return r.stdout.strip()
