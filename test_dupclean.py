import logging
from traceback import extract_stack
import tempfile
import shutil
import os
import unittest
import errno
import collections

from dup import find_files, uniques, duplicates, cleanup, exclude, scan_files

from colltools import for_each

logging.basicConfig(level='DEBUG')
#for handler in logging.root.handlers:
#    handler.addFilter(logging.Filter('test_dupclean.TestDup.test_permissions'))


class DataGenerator():
    def __init__(self, root_path=None, path_prefix='data-generator.', clean_on_exit=False, logger=None):
        self._path_prefix = path_prefix
        self._clean_on_exit = clean_on_exit
        self._root_path = root_path
        self.logger = logger or logging.getLogger(type(self).__name__)

    def __enter__(self):
        self._mkdirs_safe(self._root_path)

        self.data_path = tempfile.mkdtemp(prefix=self._path_prefix, dir=self._root_path)
        self.files = []

        return self

    def _assert(self, cond, msg):
        if not cond:
            raise Exception(msg)

    def __exit__(self, type, value, tb):
        self._assert(
            os.path.basename(self.data_path).startswith(self._path_prefix),
            "{} != {}".format(self.data_path, self._path_prefix)
        )

        if self._clean_on_exit:
            self.logger.debug('removing temp test directory: {}'.format(self.data_path))
            try:
                shutil.rmtree(self.data_path)
            except:
                for cwd, dirnames, filenames in os.walk(self.data_path):
                    for dir in dirnames:
                        os.chmod(os.path.join(cwd, dir), 0o777)
                    for file in filenames:
                        os.chmod(os.path.join(cwd, file), 0o666)
                shutil.rmtree(self.data_path)

        self.files = None

    def _mkdirs_safe(self, p):
        if not os.path.exists(p):
            os.makedirs(p)
        return p

    def chmod(self, p, mods):
        p = '{}/{}'.format(self.data_path, p)
        self.logger.debug('changing permissions of {} to {}'.format(p, oct(mods)))
        os.chmod(p, mods)

    def _mkdirs(self, relative_path):
        abspath = self.abs_path(relative_path)
        self._mkdirs_safe(abspath)

        return abspath

    def abs_path(self, relative_path):
        return os.path.abspath(os.path.join(self.data_path, relative_path))

    def create_file(self, file_path, size=4097, readable=True):
        abs_dirname = self._mkdirs(os.path.dirname(file_path))
        abs_fullname = os.path.join(abs_dirname, os.path.basename(file_path))

        self._assert(
            not os.path.exists(abs_fullname),
            'Test data will overwrite existing file: {}'.format(abs_fullname)
        )

        with open(abs_fullname, 'wb') as f:
            f.write(os.urandom(size))

        if not readable:
            os.chmod(abs_fullname, 0o200)

        self.logger.debug("created{}temporary file {}".format(
            ' read only ' if not readable else ' ', abs_fullname))

        return abs_fullname

    def copy_file(self, origin, dest):
        dest_basename = os.path.basename(dest)
        dest_dirname = os.path.dirname(dest)

        abs_dest_dirname = self._mkdirs(dest_dirname)
        abs_dest_fullname = abs_dest_dirname + '/' + dest_basename

        self._assert(
            not os.path.exists(abs_dest_fullname),
            'Test data will overwrite existing file: {}'.format(abs_dest_fullname)
        )

        shutil.copy(self.abs_path(origin), abs_dest_fullname)

        self.logger.debug("{} copied to {}".format(origin, abs_dest_fullname))

        self.files.append(abs_dest_fullname)

        return abs_dest_fullname

    def create_duplicate_set(self, paths, size=4097):
        origin = paths[0]
        origin_fullname = self.create_file(origin, size)
        l = [origin_fullname]

        for clone_name in paths[1:]:
            clone_fullname = self.copy_file(origin, clone_name)
            l.append(clone_fullname)

        return set(l)

    def symlink(self, origin, dest):
        dest_basename = os.path.basename(dest)
        dest_dirname = os.path.dirname(dest)

        abs_dest_dirname = self._mkdirs(dest_dirname)
        abs_dest_fullname = os.path.join(abs_dest_dirname, dest_basename)

        self._assert(
            not os.path.exists(abs_dest_fullname),
            'Test data will overwrite existing file: {}'.format(abs_dest_fullname)
        )

        os.symlink(self.abs_path(origin), abs_dest_fullname)

        self.logger.debug("{} linked to {}".format(origin, abs_dest_fullname))

        self.files.append(abs_dest_fullname)

        return abs_dest_fullname

    def create_uniques(self, uniques):
        for unique in uniques:
            readable = unique['readable'] if 'readable' in unique else True

            self.create_file(unique['file'], unique['size'], readable)

    def create_duplicates(self, duplicates):
        for duplicate_set in duplicates:
            self.create_duplicate_set(duplicate_set['files'], duplicate_set['size'])

    def create_links(self, links):
        for link in links:
            self.symlink(link['source'], link['dest'])


class TestCleanup(unittest.TestCase):
    def test_happy_path(self):
        def clean_others(dups):
            # Protect the first element and remove the rest
            dups.pop(0)
            return dups

        def cluster():
            return ['a.data', 'b.data', 'c.data']

        expected = {'b.data', 'c.data'}
        self._run_test(cluster, clean_others, expected)

    def test_cant_remove_all(self):
        def clean_everything(cluster):
            # Return everything
            return cluster

        def cluster():
            return ['./some_file']

        expected = set()

        self._run_test(cluster, clean_everything, expected)

    def test_cant_create_broken_links(self):
        """
        There's a file and a link to the file,
        and we choose to remove the file leaving as a result a broken link
        """

        cluster_data = []

        def cluster():
            return cluster_data

        def clean_real_file(cluster):
            return { f for f in cluster if not os.path.islink(f) }

        test_name = extract_stack()[-1][2]
        with DataGenerator(root_path='.test-data', path_prefix='{}.'.format(test_name)) as sandbox:
            cluster_data.append(sandbox.create_file('a.data'))
            cluster_data.append(sandbox.symlink('a.data', 'a.lnk'))

            expected = set()

            self._run_test(cluster, clean_real_file, expected)

    def test_cant_remove_more(self):
        def cluster():
            return ['./some_file']

        def clean_something_more(cluster):
            cluster.append('./something_else')
            return cluster

        expected = set()

        self._run_test(cluster, clean_something_more, expected)

    def test_cant_remove_something_not_in_cluster(self):
        def clean_something_else(cluster):
            # Return something else
            return ['./something_else']

        def cluster():
            return ['./some_file']

        expected = set()

        self._run_test(cluster, clean_something_else, expected)

    def _run_test(self, cluster, collect_to_remove, expected):
        logger, test_name = _getLogger(self)

        title = '==================== {} ===================='.format(test_name)
        logger.debug(title)

        logger.debug('- to clean cluster: %s', cluster())
        logger.debug('- selected to clean: %s', collect_to_remove(cluster()))
        logger.debug('- expected to have been cleaned: %s', repr(expected))

        cleaned = set()
        cleanup_func = cleanup(collect_to_remove, clean_action=cleaned.add)

        cleanup_func(cluster())

        logger.debug('- cleaned %s', cleaned)
        self.assertEqual(expected, cleaned)

        logger.debug(''.join('=' for _ in range(len(title))))


class TestDup(unittest.TestCase):
    def test_scan_files(self):
        files = [
            { 'file': '1/b.data', 'size': 4097 },
            { 'file': '2/c.data', 'size': 4096 },
            { 'file': '3/d.data', 'size': 512 },
            { 'file': '1/e.data', 'size': 4097 },
            { 'file': '4/x.unreadable', 'size': 2048, 'readable': False },
            { 'file': '4/xx.unreadable', 'size': 2048, 'readable': False },
        ]
        unaccessible = [
            { 'file': 'unexecutable/a.data', 'size': 10 },
            { 'file': 'unexecutable/1/a.data', 'size': 10 },
            { 'file': 'unreadable/a.data', 'size': 10 },
            { 'file': 'unreadable/1/a.data', 'size': 10 }
        ]

        test_name = extract_stack()[-1][2]
        logger = logging.getLogger('{}.{}.{}'.format(self.__module__, self.__class__, test_name))
        with DataGenerator(root_path='.test-data', path_prefix='{}.'.format(test_name)) as sandbox:
            sandbox.logger = logger

            sandbox.create_uniques(files)
            sandbox.create_uniques(unaccessible)

            sandbox.chmod('unreadable', 0o300)
            sandbox.chmod('unexecutable', 0o600)

            expected = [os.path.join(sandbox.data_path, f['file']) for f in files]
            found = set(scan_files(sandbox.data_path))

        self.assertEqual(len(set(expected)), len(found))
        self.assertEqual(set(expected), found)

    def test_happy_path(self):
        duplicates = [
            { 'files': ('1/a.data', '2/a.data', '3/a.data', '4/a.data'), 'size': 4097 },  # 4097 = block size + 1
            { 'files': ('2/aa.data', '4/aa.data'), 'size': 4096 },
            { 'files': ('1/aaa.data', '4/aaa.data'), 'size': 1024 },
            { 'files': ('1/aaaa.data', '3/aaaa.data'), 'size': 0 }
        ]
        uniques = [
            { 'file': '1/b.data', 'size': 4097 },
            { 'file': '2/c.data', 'size': 4096 },
            { 'file': '3/d.data', 'size': 512 },
            { 'file': '1/e.data', 'size': 4097 },
        ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(duplicates)

        def parameters(sandbox):
            return (sandbox.data_path, duplicates, uniques)

        self._run_test(gen_scenario, parameters)

    def test_permissions(self):
        unreadable_duplicates = [
            { 'files': ('/a.data', '2/a.data', '3/a.data', '4/a.data'), 'size': 4097 },  # 4097 = block size + 1
        ]
        duplicates = [
            { 'files': ('1/a.data', '2/a.data', '3/a.data', '4/a.data'), 'size': 4097 },  # 4097 = block size + 1
            { 'files': ('2/aa.data', '4/aa.data'), 'size': 4096 },
            { 'files': ('1/aaa.data', '4/aaa.data'), 'size': 1024 },
            { 'files': ('1/aaaa.data', '3/aaaa.data'), 'size': 0 }
        ]
        uniques = [
            { 'file': '1/b.data', 'size': 4097 },
            { 'file': '2/c.data', 'size': 4096 },
            { 'file': '3/d.data', 'size': 512 },
            { 'file': '1/e.data', 'size': 4097 },
            { 'file': '4/x.data', 'size': 2048, 'readable': False },
            { 'file': '4/xx.data', 'size': 2048, 'readable': False },
        ]
        unaccessible_uniques = [
            { 'file': 'unexecutable/a.data', 'size': 10 }
        ]
        unaccessible_dups = [
            { 'files': ('unreadable/1/aaaa.data', 'unreadable/3/aaaa.data'), 'size': 10 },
            { 'files': ('unexecutable/1/aaaa.data', 'unexecutable/3/aaaa.data'), 'size': 10 }
        ]
        unreadable_dup = [
            { 'files': ('1/data.readable', '3/data.unreadable'), 'size': 100 }
        ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_uniques(unaccessible_uniques)
            sandbox.create_duplicates(duplicates)
            sandbox.create_duplicates(unaccessible_dups)
            sandbox.create_duplicates(unreadable_dup)

            sandbox.chmod('unreadable', 0o300)
            sandbox.chmod('unexecutable', 0o600)
            sandbox.chmod('3/data.unreadable', 0o300)

        def parameters(sandbox):
            # Expected uniques = uniques + unreadable duplicate pair
            expected_uniques = list(uniques)
            expected_uniques.extend({ 'file': t } for d in unreadable_dup for t in d['files'])

            return (sandbox.data_path, duplicates, expected_uniques)

        self._run_test(gen_scenario, parameters)

    def test_relative_absolute_paths(self):
        duplicates = [
            { 'files': ('1/a.data', '2/a.data', '3/a.data', '4/a.data'), 'size': 4097 },  # 4097 = block size + 1
            { 'files': ('2/aa.data', '4/aa.data'), 'size': 4096 },
            { 'files': ('1/aaa.data', '4/aaa.data'), 'size': 1024 },
            { 'files': ('1/aaaa.data', '3/aaaa.data'), 'size': 0 }
        ]
        uniques = [
            { 'file': '1/b.data', 'size': 4097 },
            { 'file': '2/c.data', 'size': 4096 },
            { 'file': '3/d.data', 'size': 512 },
            { 'file': '1/e.data', 'size': 4097 },
            { 'file': '4/x.data', 'size': 2048, 'readable': False },
            { 'file': '4/xx.data', 'size': 2048, 'readable': False }
        ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(duplicates)

        def parameters(sandbox):
            return ((sandbox.data_path, os.path.abspath(sandbox.data_path)), duplicates, uniques)

        self._run_test(gen_scenario, parameters, root_path='./.test-data')

    def test_outside_links(self):
        def gen_scenario(sandbox):
            dups = [
                { 'files': ('1/a.data', '2/a.data'), 'size': 512 }
            ]
            uniques = []
            links = [
                { 'source': '2/a.data', 'dest': '1/2.a.lnk' }
            ]

            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(dups)
            sandbox.create_links(links)

        def parameters(s):
            dups = [
                { 'files': ('1/2.a.lnk', '1/a.data'), 'size': 512 }
            ]
            uniques = []
            return (os.path.join(s.data_path, '1') , dups, uniques)

        self._run_test(gen_scenario, parameters)


    def test_broken_links(self):
        """
        We don't care whether the links are broken. They are just considered as uniques
        """
        def gen_scenario(sandbox):
            dups = []
            uniques = []
            links = [
                { 'source': 'a.data', 'dest': 'a.lnk' },
                { 'source': 'b.data', 'dest': 'a2.lnk' }
            ]

            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(dups)
            sandbox.create_links(links)

        def parameters(s):
            uniques = [
                { 'file': 'a.lnk', 'size': 1 },
                { 'file': 'a2.lnk', 'size': 1 },
            ]
            return (s.data_path, [], uniques)

        self._run_test(gen_scenario, parameters)

    def test_multiple_inputs(self):
        dups = [
            { 'files': ('1/a.data', '2/a.data', '3/a.data', '4/a.data'), 'size': 512 }
        ]
        uniques = [ { 'file': '5/b.data', 'size': 4097 } ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(dups)

        def parameters(s):
            where = [os.path.join(s.data_path, dir) for dir in (os.path.dirname(d) for d in dups[0]['files'])]
            for d in (dir['file'] for dir in uniques):
                where.append(os.path.join(s.data_path, d))

            return (where , dups, uniques)

        self._run_test(gen_scenario, parameters)

    def test_same_input_twice(self):
        duplicates = []
        uniques = [ { 'file': 'a.data', 'size': 10 } ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(duplicates)

        def parameters(sandbox):
            return ((sandbox.data_path, sandbox.data_path), duplicates, uniques)

        self._run_test(gen_scenario, parameters)

    def test_file_as_input(self):
        duplicates = []
        uniques = [ { 'file': 'a.data', 'size': 10 } ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(duplicates)

        def parameters(s):
            return (
                (s.data_path, '{}/a.data'.format(s.data_path), '{}/a.data'.format(s.data_path)),
                duplicates,
                uniques
            )

        self._run_test(gen_scenario, parameters)

    def test_linked_dir(self):
        duplicates = []
        uniques = [ { 'file': '1/nested/a.data', 'size': 10 } ]
        links = [
            { 'source': '1', 'dest': '1.lnk' },
            { 'source': '1/nested', 'dest': 'nested.lnk' },
            { 'source': 'nested.lnk', 'dest': 'nested.lnk.lnk' }
        ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(duplicates)
            sandbox.create_links(links)

        def parameters(sandbox):
            return ((sandbox.data_path, os.path.join(sandbox.data_path, 'nested.lnk')), duplicates, uniques)

        self._run_test(gen_scenario, parameters)

    def test_linked_file(self):
        duplicates = []
        uniques = [ {'file': 'a.data', 'size': 10 } ]
        links = [
            {'source': 'a.data', 'dest': 'a.lnk' },
            {'source': 'a.lnk', 'dest': 'a.lnk.lnk' }
        ]

        def gen_scenario(sandbox):
            sandbox.create_uniques(uniques)
            sandbox.create_duplicates(duplicates)
            sandbox.create_links(links)

        def parameters(sandbox):
            return (sandbox.data_path, duplicates, uniques)

        self._run_test(gen_scenario, parameters)

    def _run_test(self, gen_scenario, parameters, root_path='./.test-data'):
        def find(which, where):
            result = []
            find_files(which, where, result.append)

            return { tuple(cluster) for cluster in result }

        def run_safe(what, where):
            try:
                return find(what, where)
            except e:
                return e

        logger, test_name = _getLogger(self)

        title = '==================== {} ===================='.format(test_name)
        logger.debug(title)

        with DataGenerator(root_path=root_path, path_prefix='{}.'.format(test_name)) as sandbox:
            sandbox.logger = logger

            logger.debug('SCENARIO:')
            gen_scenario(sandbox)
            where, expected_dups, expected_uniques = parameters(sandbox)

            if isinstance(expected_dups, collections.Iterable):
                expected_dups = { tuple(os.path.join(sandbox.data_path, f) for f in d['files']) for d in expected_dups }

            if isinstance(expected_uniques, collections.Iterable):
                expected_uniques = { tuple([os.path.join(sandbox.data_path, u['file'])]) for u in expected_uniques }

            result_duplicates = run_safe(duplicates, where)
            result_uniques = run_safe(uniques, where)

            logger.debug('---')
            logger.debug('RESULTS:')
            logger.debug('scanning: %s', where)
            logger.debug('- expected uniques: %s', expected_uniques)
            logger.debug('-    found uniques: %s', result_uniques)
            logger.debug('--')
            logger.debug('- expected duplicates: %s', expected_dups)
            logger.debug('-    found duplicates: %s', result_duplicates)

            _assertEqual(self, expected_dups, result_duplicates)
            _assertEqual(self, expected_uniques, result_uniques)

        logger.debug(''.join('=' for _ in range(len(title))))


class TestKeep(unittest.TestCase):
    def test_keep_relative_path(self):
        cwd = os.path.abspath('.')
        cluster = { 'a', './a', './x/a', '/b', '/x/b', '../b', os.path.join(cwd, 'a') }
        expected = { '/b', '/x/b', '../b' }

        self._run_test(cluster, expected, '.')

    def test_keep_absolute_path(self):
        cwd = os.path.abspath('.')
        cluster = { 'a', './a', './x/a', '/b', '/x/b', '../b', os.path.join(cwd, 'a') }
        expected = { '/b', '/x/b', '../b' }

        self._run_test(cluster, expected, cwd)

    def test_keep_multiple(self):
        with tempfile.NamedTemporaryFile() as tmp:
            cwd = os.path.abspath('.')
            cluster = { 'a', './a', tmp.name, '/b', '/x/b', '../b', os.path.join(cwd, 'a') }
            expected = { '/b', '/x/b', '../b' }
            protected = [ tmp.name, '.' ]

            self._run_test(cluster, expected, *protected)

    def test_keep_file(self):
        with tempfile.NamedTemporaryFile() as tmp:
            protected = tmp.name
            cwd = os.path.abspath('.')
            cluster = { 'a', './a', protected, '/b', '/x/b', '../b', os.path.join(cwd, 'a') }
            expected = cluster - set([protected])

            self._run_test(cluster, expected, protected)

    def test_enoent(self):
        cwd = os.path.abspath('.')
        cluster = { 'a', './a', './x/a', '/b', '/x/b', '../b', os.path.join(cwd, 'a') }
        enoent = './not-existing'
        expected = IOError(errno.ENOENT, 'No such file or directory: {}'.format([enoent]))

        self._run_test(cluster, expected, enoent)

    def _run_test(self, cluster, expected, *keep_path):
        try:
            keep_func = exclude(*keep_path)
            result = set(keep_func(cluster))
        except IOError as e:
            result = e

        logger, test_name = _getLogger(self)

        title = '==================== {} ===================='.format(test_name)
        logger.debug(title)
        logger.debug('           keep_path: %s', keep_path)
        logger.debug('             cluster: %s', cluster)
        logger.debug(' expected disposable: %s', expected)
        logger.debug('   result disposable: %s', result)
        logger.debug(''.join('=' for _ in range(len(title))))

        _assertEqual(self, expected, result)


def _assertEqual(self, expected, actual):
    # This function is needed because two instances of the same exception are not equal
    if isinstance(expected, Exception) and isinstance(actual, Exception):
        self.assertEqual(type(expected), type(actual))
        self.assertEqual(expected.args, actual.args)
    else:
        self.assertEqual(expected, actual)

def _getLogger(obj):
    test_name = extract_stack()[-3][2]
    return (logging.getLogger('{}.{}.{}'.format(__name__, type(obj).__name__, test_name)), test_name)
