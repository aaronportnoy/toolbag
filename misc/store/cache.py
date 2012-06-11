# cache.py
#
# for public release, 2012
#
# Ali Rizvi-Santiago


import logging
from datetime import datetime

import driver,trigger
import query

logging.root=logging.RootLogger(logging.DEBUG)

class trigger(trigger.__base__):
    '''ID=node address'''

class watch(set):
    def __init__(self, view, tags):
        self.view = view
        super(watch,self).__init__()
        super(watch,self).update(tags)
        return None

    def add(self, *tag):
        self.view.dirty()

        result = self.watch.difference(set(tag))
        super(watch,self).update(tag)

        for i,ea in enumerate(self.view.node):
            [self.view.callback((ea,n)) for n in result]
        return len(result)

    def discard(self, *tag):
        # XXX: remove the specified tags from the view.render store
        #      on the next update
        raise NotImplementedError
        view = self.view
        for i,ea in enumerate(self.view.node):
            view.trigger.add(ea, lambda *args,**kwds: update.discard_context(self,*args,**kwds))
            [view.trigger.add((ea,n), lambda *args,**kwds: update.discard_content(self,*args,**kwds)) for n in tag]
        return

class update:
    # callbacks for some content
    @staticmethod
    def context(self, node, update):
        logging.debug('updating %x with %s'%(node.id,repr(update)))
        for key,value in update.iteritems():
            self.render.address(node.id)[key] = value
        return

    @staticmethod
    def content(self,(node,name), update):
        logging.debug('updating %x:%s with %s'%(node.id,name,repr(update)))
        for ea,value in update.iteritems():
            self.render.address(node.id).address(ea)[name] = value
        return

    @staticmethod
    def discard_context(self, node, *tags):
        r = self.render.address(node.id)

        # context
        [del(r[n]) for n in tags]
        # content
        [update.discard_content(self, node, *tags)]
        # tags
        [self.watch.discard(n) for n in tags]

        [self.trigger.remove((ea,n)) for n in tags]
        for i,ea in self.node.values():
            [self.trigger.remove((ea,n)) for n in tags]
        return

    @staticmethod
    def discard_content(self, node, *tags):
        r = self.render.address(node.id)
        for ea in r.select(query.attribute(*tags)):
            [del(r.address(ea)[n]) for n in tags]
        [self.watch.discard(n) for n in tags]
        return

class view(object):
    '''
    this groups multiple record sources together and provides an interface for
    selecting/modifying nodes in a query. this can be used to update recordsets to update a graph.
    '''
    node = dict     # list of nodes to watch

    def __init__(self, store, render, tags=set()):
        self.node = {}

        self.store = store              # data store
        self.render = render            # render store
        self.watch = watch(self, tags)  # default tags to transfer
        self.trigger = trigger()        # callback object

        self.dirty()
        self.update()
        return

    def __repr__(self):
        nodes = '[%s]'%(','.join(map(hex,self.node.keys())))
        return '%s %s node:%s'%(type(self), repr(self.watch), nodes)

    ## syncing records with db
    def dirty(self):
        self.__age = datetime(1,1,1)    # near epoch
        return

    def commit(self):
        return self.store.commit()

    def rollback(self):
        self.store.rollback()
        self.dirty()
        return self.update()

    def callback(self, address, n=None):
        ''' add callback to the specific node address '''
        id = ((self.node[ea].id,n), self.node[ea].id)[n is None]
        self.trigger.remove(id)
        if n:
            return self.trigger.add(id, lambda *args,**kwds: update.content(self, *args, **kwds))
        return self.trigger.add(id, lambda *args,**kwds: update.context(self, *args, **kwds))

    def update(self):
        ''' call this every once in a while '''
        # context
        if not self.watch:
            logging.info('refusing to update due to an empty tag list')
            return {}

        # query all contexts and update nodes
        result = {}
        for k,v in self.store.select(query.newer(self.__age),query.attribute(*self.watch),query.address(*self.node.keys())).iteritems():
            if not v:
                continue
            self.node[k].update(v)
            result[k] = v

        # execute callback for all nodes
        for address,updates in result.iteritems():
            node = self.node[address]
            if self.trigger.execute(node.id, node, updates):
                logging.warning('callback for %x returned non-zero value')
            continue

        completed = set(result.keys())

        # now for content
        for address in self.node:
            result = self.store.select_content(query.newer(self.__age),query.attribute(*self.watch),query.context(address))

            node = self.node[address]
            names = set()

            # collect names for updates
            for ea,d in result.iteritems():
                names.update(d.keys())

            # callbacks for content
            for n in names:
                r = ((ea,d[n]) for ea,d in result.iteritems() if n in d)
                self.trigger.execute((node.id,n), (node,n), dict(r))

            node.content.update(result)

        self.__age = datetime.now()
        return completed

    ## adding nodes to view
    def __add(self, *address):
        '''add a list of addresses to the current view'''
        result = set(address).difference(set(self.node.keys()))
        if len(result) > 0:
            for i,ea in enumerate(result):
                self.node[ea] = node(self, self.store.address(ea))
                self.callback(ea)
                [self.callback((ea,n)) for n in self.watch]
            return i+1
        return 0

    def extend(self, *q):
        '''extend the current view with other nodes using the given query'''
        return self.__add( *self.store.select(*q).keys() )

    ## modifying current view
    def select(self, *q):
        '''return a subview with the given query on a function's context'''
        result = type(self)(self.store, self.watch)
        if self.node:
            nodes = tuple(k for k in self.node.iterkeys())
            result.extend(query.address(*nodes))
        return result

    def grow(self, depth):
        result = type(self)(self.store, self.watch)
        result.__add(*self.node.keys())
        for k,v in self.iteritems():
            result.extend(query.depth(k, depth))
        return result

class node(dict):
    id = property(fget=lambda s:s.__id)
    view = None     # the view we belong to
    store = property(fget=lambda s:s.view.store)
    data = property(fget=lambda s:s.__data)

    # node navigation
    def __init__(self, view, ctx):
        self.__id = ctx.id
        self.__data = ctx
        self.view = view
        self.content = {}

    def up(self):
        return set(self.store.select(query.depth(self.id,-1)).keys())
    def down(self):
        return set(self.store.select(query.depth(self.id,1)).keys())

    # fronting a dictionary
    def __repr__(self):
        return '%s 0x%08x %s len(content):%d'%(type(self), self.id, super(node,self).__repr__(), len(self.content))

    def select(self, *q):
        ''' perform a query on this node's contents '''
        return self.data.select(*q)
   
