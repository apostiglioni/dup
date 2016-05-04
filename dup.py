import os
import errno
import logging

from copy import copy
from filecmp import cmp
from functools import partial
from hashlib import md5

from colltools import for_each

def all_files(tops):
    return [scan_files(tops)]

def scan_files(tops):
    """Lists all files in the given directories."""

    logger = _getLogger('scan_files')

    def verify_access(p, showname = None):
        if not os.access(p, os.R_OK):
            logger.warning("Permission denied to read %s", showname or p)
        elif not os.path.isfile(p) and not os.access(p, os.X_OK):
            logger.warning("Permission denied to walk through %s", showname or p)

    dups = []
    tops = (tops,) if isinstance(tops, str) else tops

    for top in tops:
        verify_access(top)

        if os.path.isfile(top):
            if os.path.realpath(top) not in dups:
                dups.append(os.path.realpath(top))
                yield top
        else:
            for cwd, dirnames, filenames in os.walk(top):

                if not os.access(cwd, os.X_OK):
                    # If dir is unaccessible, files cannot be read and we can't diferentiate between files and dirs.
                    # We will treat this case as if the dir was unreadable
                    continue

                for dir in dirnames:
                    dir = os.path.join(cwd, dir)
                    verify_access(dir)

                for file in filenames:
                    file = os.path.join(cwd, file)
                    realpath = os.path.realpath(file)

                    verify_access(realpath, file)

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
                logger = _getLogger('partition')
                logger.warning('Exception while generating %s key for %s, generating random key.', partitioner.__name__, item)
                logger.debug(e)

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
    digest_func = partial(digest, method=method)
    digest_func.__name__ = method.__name__  # Give partial a name so we can log it pretty if it fails

    return lambda groups: partition(groups, digest_func)

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

def find_files(which, where, action):
    for_each(
        which(
            group_by_size_hash_content(
                all_files(where)
            )
        ),
        action = action
    )

def cleanup(selector, clean_action=None):
    """
    Returns a cleanup function that receives a cluster of files.
    The returned function validates that applying the given selector to the to the cluster of files will not cause
    data loss, and if safe, applies the given clean_action or, if no clean_action is given, a default remove function
    to the selected items cluster.

    :param selector: A function that takes a cluster of files and returns the subset to clean
    :param clean_action: The action to execute for each element of the subset to clean
    """

    logger = _getLogger('cleanup')

    def validate_excluded(subset, original):
        """
        This function is used to validate that removing the given subset from the original set will not cause
        data loss.
        It returns the given subset if valid, or a new empty set if invalid.

        Validates that:
         * subset is not empty.
         * subset is a strict subset of original.
         * each element in the original set but not in the subset (original - subset) is not a link to an element in
           subset.
        """

        subset = set(subset)
        original = set(original)
        excluded = original - subset

        logger.debug('processing cluster %s', original)

        if len(subset) == 0:
            logger.warning('Ignoring cluster %s', original)
            return ()

        if not subset.issubset(original) or original == subset:
            logger.warning('Skipping cluster %s. Not a strict subset: %s.', list(original), list(subset))
            return ()

        for p in excluded:
            if os.path.islink(p) and os.path.realpath(p) in { os.path.realpath(f) for f in subset }:
                logger.warning('Skipping cluster %s. Cleanup of %s would create a broken link: %s', list(original), list(subset), p)
                return ()

        return subset

    return partial(process_cluster, transform=selector, validate=validate_excluded, action=clean_action or remove)

def remove(a):
    pass

def exclude(*secured):
    """
    Returns a function that receives a cluster of files. The new function returns the files in the cluster that
    are not secured.

    A file is considered secured if it's path is not under the tree of those elements passed as arguments to the
    original function.

    If any of the 'secured' paths does not exist, an exception is thrown.
    """

    def _exclude(cluster):
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
        raise IOError(errno.ENOENT, 'No such file or directory: {}'.format(unsecured))

    return _exclude

def _getLogger(name):
    return logging.getLogger('{}.{}'.format(__name__, name))

