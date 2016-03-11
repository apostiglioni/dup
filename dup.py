import os
import errno
import logging

from copy import copy
from filecmp import cmp
from functools import partial
from hashlib import md5

from colltools import for_each

def all_files(tops, strict_walk=True):
    return [scan_files(tops, strict_walk)]

def scan_files(tops, strict_walk):
    """Lists all files in the given directories."""
    tops = (tops,) if isinstance(tops, str) else tops

    dups = []

    for top in tops:
        if os.path.isfile(top):
            if os.path.realpath(top) not in dups:
                dups.append(os.path.realpath(top))
                yield top
        else:
            for cwd, dirnames, filenames in os.walk(top):
                if strict_walk:
                    for dir in dirnames:
                        dir = os.path.join(cwd, dir)
                        if not os.access(dir, os.R_OK) or not os.access(dir, os.X_OK):
                            raise WalkError.permission_denied(dir)

                for file in filenames:
                    file = os.path.join(cwd, file)
                    realpath = os.path.realpath(file)

                    if strict_walk and not os.access(realpath, os.R_OK):
                        raise WalkError.permission_denied(file)

                    if realpath not in dups:
                        dups.append(realpath)
                        yield file


def digest(file, method=md5):
    m = method()
    with open(file, 'rb') as f:
        # b'' == EOF
        for chunk in iter(lambda: f.read(m.block_size * 64), b''):
            m.update(chunk)

    hash_value = m.hexdigest()

    return hash_value

def by_content(groups):
    """
    Compare the given files, breaking them down into groups with identical
    content.
    """
    for group in groups:
        files = list(group)
        while len(files) > 0:
            next_set = []
            this_set = []

            master = files[0]
            this_set.append(master)

            for other in files[1:]:
                if cmp(master, other, False):
                    this_set.append(other)
                else:
                    next_set.append(other)

            yield this_set
            files = next_set

def partition(groups, partitioner, fail_safe=True):
    """
    Breaks each of the groups into smaller subgroups.
    returns a generator of subgroups (each element of the generator is a subgroup)
    """
    def generate_key(item, subgroups):
        try:
            k = partitioner(item)
        except Exception as e:
            if fail_safe:
                from random import random
                k = random()
                while k in subgroups.keys():
                    k = random()
            else:
                raise e
        return k

    for group in groups:
        subgroups = {}
        for item in group:
            k = generate_key(item, subgroups)

            if k not in subgroups.keys():
                subgroups[k] = []

            subgroups[k].append(item)
        for g in subgroups.values():
            yield g

def by_hash(method):
    return lambda groups: partition(groups, lambda file: digest(file, method))

def by_size(groups):
    return partition(groups, os.path.getsize)

def group(partitioners, cluster):
    for partitioner in partitioners:
        cluster = partitioner(cluster)
    return cluster

def group_by_size_hash_content(files, hash_method=md5):
    """
    Groups the files by size, hash and content
    """
    return group([by_size, by_hash(hash_method), by_content], files)

def filter_by(criteria, clusters):
    for cluster in clusters:
        if criteria(cluster):
            yield cluster

def duplicates(clusters):
    return filter_by(lambda x: len(x) > 1, clusters)

def uniques(clusters):
    return filter_by(lambda x: len(x) == 1, clusters)

def process_cluster(cluster, transform, validate, action):
    for_each(
        validate(
            transform(copy(cluster)),
            cluster
        ),
        action = action
    )

def find_files(which, where, action, strict_walk=True):
    for_each(
        which(
            group_by_size_hash_content(
                all_files(where, strict_walk=strict_walk)
            )
        ),
        action = action
    )

def cleanup(transform, clean_action=None):
    logger = logging.getLogger('{}.cleanup'.format(__name__))

    def validate_excluded(subset, original):
        """
        For each cluster in clusters, applies the given predicate.
        Assumes that predicate returns a subset of the original cluster, and that the items removed are existing files.
        Should the assumptions be false, an exception is thrown.
        """
        subset = set(subset)
        original = set(original)
        excluded = original - subset

        logger.debug('processing cluster %s', original)

        if len(subset) == 0:
            logger.warning('Ignoring cluster %s', original)

        if not subset.issubset(original) or len(excluded) < 1:
            logger.warning('Skipping cluster %s. Not a subset: %s.', original, subset)
            return ()
#            raise CleanupError.not_subset("{} is not a subset of {}".format(subset, original))

        for p in excluded:
            if os.path.islink(p) and os.path.realpath(p) in { os.path.realpath(f) for f in subset }:
                logger.warning('Skipping cluster %s. Cleanup would create a broken link: %s', original, p)
                return ()
#                raise CleanupError.broken_link(
#                    "Removing '{}' would make '{}' a broken link".format(os.path.realpath(p), p)
#                )

        return subset

    def remove(a):
        pass

    return partial(process_cluster, transform=transform, validate=validate_excluded, action=clean_action or remove)


def keep(*secured):
    def _keep(cluster):
        secured_abspaths = [ os.path.abspath(item) for item in secured ]

        selected = []
        for file in cluster:
            for s_abspath in secured_abspaths:
                if os.path.abspath(file).startswith(s_abspath):
                    selected.append(file)
                    continue

        return [ f for f in cluster if f not in selected ]

    unsecured = [ s for s in secured if not os.path.exists(s) ]

    if len(unsecured) > 0:
        raise WalkError.no_such_file(unsecured)

    return _keep


class CleanupError(Exception):
    NOT_SUBSET = 0
    BROKEN_LINK = 1

    def __init__(self, errno, message):
        # Call the base class constructor with the parameters it needs
        super(CleanupError, self).__init__(message)

        self.errno = errno

    @staticmethod
    def broken_link(message='Broken link'):
        return CleanupError(CleanupError.BROKEN_LINK, message)

    @staticmethod
    def not_subset(message='Not subset'):
        return CleanupError(CleanupError.NOT_SUBSET, message)


class WalkError(IOError):
    @staticmethod
    def permission_denied(path):
        return WalkError(errno.EACCES, 'Permission denied: {}'.format(path))

    @staticmethod
    def no_such_file(path):
        return WalkError(errno.ENOENT, 'No such file or directory: {}'.format(path))
