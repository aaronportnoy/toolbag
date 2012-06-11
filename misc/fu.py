# fu.py
#
# for public release, 2012
#

import cPickle as pickle,marshal

def dumps(object, **kwds):
    '''Serialize objects (i.e. convert from an object to a string)'''
    return lookup.dumps(object, **kwds).encode('bz2')
def loads(s, **kwds):
    '''Deserialize objects (i.e. convert from a string back to an object)'''
    return lookup.loads(s.decode('bz2'), **kwds)

def closure(l, **kwds):
    '''Return a closure that will pass the specified named arguments to function l.'''
    # XXX: need some way of specfying/changing the global namespace
    def result(*args):
        return l(*args, **kwds)
    return result

### type serialization
# if i rewrite this as more of a protocol, i should consider the following or read what people have done with rpc
#    references: it'd be neat if each rpc object can have a reference id so that deserialization can just reference
#                the object that was created. this will prevent a list of references from being serialized twice.
#    namespaces: currently, if we serialize the .__module__ property, we can use __import__(module).__dict__ to attempt
#                to import the specified module, and snag it's namespace. this is handled by the 'namespace' parameter.
#    class:  it should be an option to serialize the code belonging to a class. if the namespace is known, we should be
#            able to copy methods from the object in the source namespace.
#    class instancemethod: in order for this to be instantiated, the 'class' needs to be known for im_self, and
#                          im_class to be assigned.
#    instance: this should be serializeable. currently the dictionary lookup searches only by types. this might be
#              really simple to work around
#    performance: this is pretty slow. i should probably benchmark this.. before that though, i should try to localize
#                 all the conditional branches and ensure use tuples for everything. only marshal necessary objects,
#                 and pack everything with cPickle

# protocol components:
#   Reference,Id,number id
#   Reference,Namespace,module name,symbol name
#   Store,Packed Type,number id,packed data
#   Store,Packed Object,number id,packed data

class lookup(dict):
    '''Used to search the marshall table'''
    class cache:
        id = {}
        type = {}

    @classmethod
    def define(cls, definition):
        id = hash(definition.__name__)
        type = definition.get()

        cls.cache.type[type] = definition
        cls.cache.id[id] = definition
        definition.id = id
        return definition

    @classmethod
    def byid(cls, id):
        return cls.cache.id[id]
    @classmethod
    def byclass(cls, type):
        return cls.cache.type[type]

    @classmethod
    def loads(cls, s, **kwds):
        id,data = marshal.loads(s)
        t = kwds.get('type', cls.byid(id))
        return t.loads(data, **kwds)

    @classmethod
    def dumps(cls, object, **kwds):
        try:
            t = kwds.get('type', cls.byclass(object.__class__))
            return marshal.dumps((t.id, t.dumps(object, **kwds)))
        except KeyError:
            # if this exception is raised, then assume that we're serializing an object instance
            raise

            # TODO: walk an instance object or pickle this in order to serialize it
            # TODO: assign these to kwds too
            kwds.get('instance', None)
            kwds.get('class', None)
        return

class __type__(object):
    '''Every marshallable type should inherit from this'''
    @classmethod
    def get(cls):
        '''Return the class that can be used to construct the object'''
        raise NotImplementedError(cls)

    @classmethod
    def loads(cls, s, **kwds):
        raise NotImplementedError(cls)

    @classmethod
    def dumps(cls, object, **kwds):
        raise NotImplementedError(cls)

    @classmethod
    def repr(cls, object):
        '''Default method for displaying a repr of the object'''
        return repr(object)

    @classmethod
    def new(cls, *args):
        return cls.get()(*args)

##
class marshallable(__type__):
    import marshal
    @classmethod
    def loads(cls, s, **kwds):
        return marshal.loads(s)

    @classmethod
    def dumps(cls, object, **kwds):
        return marshal.dumps(object)

class container(marshallable):  ## heh, again? really?
    '''A container of dumpable objects'''
    @classmethod
    def loads(cls, s, **kwds):
        object = marshal.loads(s)
        return cls.deserialize(object, **kwds)

    @classmethod
    def dumps(cls, object, **kwds):
        # convert contents to a container of strings
        serialized = cls.serialize(object)
        return marshallable.dumps(serialized, **kwds)

    @classmethod
    def serialize(cls, object, **kwds):
        '''Should need to convert object into a marshallable container of marshallable types'''
        raise NotImplementedError(cls)

    @classmethod
    def deserialize(cls, object, **kwds):
        '''Should expand serializeable object back into it's native type'''
        raise NotImplementedError(cls)

class special(container):
    @classmethod
    def serialize(cls, object, **kwds):
        return [(lookup.dumps(k,**kwds), lookup.dumps(getattr(object, k),**kwds)) for k in cls.attributes]

    @classmethod
    def deserialize(cls, object, **kwds):
        object = [((lookup.loads(k,**kwds)), (lookup.loads(v,**kwds))) for k,v in object]
        object = __builtins__['dict'](object)
        return cls.deserialize_dict(object, **kwds)

### atomic marshallable types
@lookup.define
class int(marshallable):
    @classmethod
    def get(cls):
        return (0).__class__

@lookup.define
class str(marshallable):
    @classmethod
    def get(cls):
        return ''.__class__

@lookup.define
class unicode(marshallable):
    @classmethod
    def get(cls):
        return u''.__class__

@lookup.define
class none(marshallable):
    @classmethod
    def get(cls):
        return None.__class__

@lookup.define
class long(marshallable):
    @classmethod
    def get(cls):
        return (0L).__class__

### containers of types
@lookup.define
class list(container):
    @classmethod
    def get(cls):
        return [].__class__

    @classmethod
    def serialize(cls, object, **kwds):
        return [ lookup.dumps(x, **kwds) for x in object ]

    @classmethod
    def deserialize(cls, object, **kwds):
        return [ lookup.loads(x, **kwds) for x in object ]

@lookup.define
class tuple(container):
    @classmethod
    def get(cls):
        return ().__class__

    @classmethod
    def serialize(cls, object, **kwds):
        return __builtins__['tuple']([lookup.dumps(x, **kwds) for x in object])

    @classmethod
    def deserialize(cls, object, **kwds):
        return __builtins__['tuple']([lookup.loads(x) for x in object])

@lookup.define
class dict(container):
    @classmethod
    def get(cls):
        return {}.__class__

    @classmethod
    def serialize(cls, object, **kwds):
        return [ (lookup.dumps(k, **kwds), lookup.dumps(v, **kwds)) for k,v in object.items() ]

    @classmethod
    def deserialize(cls, object, **kwds):
        return __builtins__['dict']( (lookup.loads(k, **kwds), lookup.loads(v, **kwds)) for k,v in object )

if False:
    @lookup.define
    class module(container):
        @classmethod
        def get(cls):
            return __builtins__.__class__

        # TODO: need to store each module's contents along with its name
        @classmethod
        def serialize(cls, object, **kwds):
            return [ (lookup.dumps(k, **kwds), lookup.dumps(v, **kwds)) for k,v in object.__dict__.items() ]

        # TODO: instantiate a new module, and then set all of its attributes
        #       (or modify it's __dict__)
        @classmethod
        def deserialize(cls, object, **kwds):
            c = cls.get()
            return __builtins__['dict']( (lookup.loads(k, **kwds), lookup.loads(v, **kwds)) for k,v in object )

### special types
@lookup.define
class function(special):
    attributes = ['func_code', 'func_name', 'func_defaults', '__module__']

    @classmethod
    def serialize(cls, object, **kwds):
        result = [(lookup.dumps(k,**kwds), lookup.dumps(getattr(object, k),**kwds)) for k in cls.attributes]

        func_closure = getattr(object, 'func_closure')
        if func_closure is None:
            return result + [(lookup.dumps('func_closure'), lookup.dumps(func_closure, type=none))]
        return result + [(lookup.dumps('func_closure'), lookup.dumps(func_closure, type=cell))]

    @classmethod
    def get(cls):
        return (lambda:False).__class__

    @classmethod
    def new(cls, code, globals, **kwds):
        '''Create a new function'''
        name = kwds.get('name', code.co_name)
        argdefs = kwds.get('argdefs', ())
        closure = kwds.get('closure', ())
        c = cls.get()
        return c(code, globals, name, argdefs, closure)

    @classmethod
    def deserialize_dict(cls, object, **kwds):
        '''Create a new function based on supplied attributes'''
        namespace = kwds.get('namespace', __import__(object['__module__']).__dict__)
        return cls.new( object['func_code'], namespace, name=object['func_name'], argdefs=object['func_defaults'], closure=object['func_closure'])

@lookup.define
class code(special):
    attributes = [
        'co_argcount', 'co_nlocals', 'co_stacksize', 'co_flags', 'co_code',
        'co_consts', 'co_names', 'co_varnames', 'co_filename', 'co_name',
        'co_firstlineno', 'co_lnotab', 'co_freevars', 'co_cellvars'
    ]

    @classmethod
    def get(cls):
        return eval('lambda:False').func_code.__class__

    @classmethod
    def deserialize_dict(cls, object, **kwds):
        result = (object[k] for k in cls.attributes)
        result = __builtins__['tuple'](result)
        return cls.new(*result)

    @classmethod
    def new(cls, argcount, nlocals, stacksize, flags, codestring, constants, names, varnames, filename='<memory>', name='<unnamed>', firstlineno=0, lnotab='', freevars=(), cellvars=()):
        i,s,t = __builtins__['int'],__builtins__['str'],__builtins__['tuple']
        types = [ i, i, i, i, s, t, t, t, s, s, i, s, t, t ]
        values = [ argcount, nlocals, stacksize, flags, codestring, constants, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars ]

        for i,t in enumerate(types):
            values[i] = t( values[i] )

        return cls.get()(*values)

@lookup.define
class instancemethod(special):
#    attributes = ['im_func', 'im_self', 'im_class']
    attributes = ['im_func']
    @classmethod
    def get(cls):
        return cls.get.__class__

    @classmethod
    def deserialize_dict(cls, object, **kwds):
        c = cls.get()
        return c( object['im_func'], kwds.get('instance', None), kwds.get('class', None) )

    @classmethod
    def new(cls, func, inst, class_):
        return cls.get()(function, instance, class_)

@lookup.define
class type(special):
    '''A class....fuck'''
    attributes = ['__name__', '__bases__']
    exclude = __builtins__['set'](['__class__','__doc__'])

    @classmethod
    def get(cls):
        return type.__class__

    @classmethod
    def deserialize_dict(cls, object, **kwds):
        namespace = __builtins__['dict'](object)
        return type.__class__(namespace['__name__'], namespace['__bases__'], namespace)

    @classmethod
    def serialize(cls, object, **kwds):
        try:
            id,type = 0,lookup.byclass(object)
            result = type.id
        except KeyError:
            id,result = 1,cls.serialize_class(object, **kwds)
        return marshal.dumps((id,result))

    @classmethod
    def deserialize(cls, object, **kwds):
        id,data = marshal.loads(object)
        if id == 0:
            return lookup.byid(data).get()
        return cls.deserialize_class(data, **kwds)

    @classmethod
    def serialize_class(cls, object, **kwds):
        # all the attributes we care about
        attrs = [(lookup.dumps(k,**kwds), lookup.dumps(getattr(object, k),**kwds)) for k in cls.attributes]

        # figure out what methods and properties we can copy
        props = []
        for n in dir(object):
            v = getattr(object, n)
            try:
                t = lookup.byclass(v.__class__)
            except KeyError:
                continue

#            if (t is type) or (n in cls.exclude):
            if n in cls.exclude:
                continue

            n,v = lookup.dumps(n, **kwds), lookup.dumps(v, **kwds)
            props.append( (n,v) )

        module = object.__module__
        return marshal.dumps( (module,(attrs,props)) )

    @classmethod
    def deserialize_class(cls, object, **kwds):
        module,(attrs,props) = marshal.loads(object)
        attrs = [((lookup.loads(k,**kwds)), (lookup.loads(v,**kwds))) for k,v in attrs]

        if 'namespace' not in kwds:
            kwds = {}.__class__(kwds)
            kwds['namespace'] = __import__(module).__dict__

        res = cls.deserialize_dict(attrs, **kwds)
        kwds['class'] = res

        for k,v in props:
            k,v = lookup.loads(k,**kwds),lookup.loads(v,**kwds)
            setattr(res, k, v)
        return res

@lookup.define
class classobj(marshallable):
    '''A class....fuck'''
    @classmethod
    def get(cls):
        t = cls.__class__.__class__
        class obj: pass
        return t(obj)

@lookup.define
class objectclass(__type__):
    @classmethod
    def get(cls):
        return __builtins__['object']

    def loads(self, string, **kwds):
        return self.new()

    def dumps(self, object, **kwds):
        return ''

@lookup.define
class bool(marshallable):
    @classmethod
    def get(cls):
        return True.__class__

@lookup.define     # FIXME: does looking up a cell object really work?
class cell(marshallable):
    class tuple(object):
        '''class that always produces a cell container'''
        def __new__(name, *args):
            return cell.new(*args)

    @classmethod
    def get(cls):
        return cls.tuple

    @classmethod
    def loads(cls, s, **kwds):
        cells = lookup.loads(s)
        return cls.new( *cells )

    @classmethod
    def dumps(cls, object, **kwds):
        result = ( x.cell_contents for x in object )
        return lookup.dumps( __builtins__['tuple'](result) )

    @classmethod
    def new(cls, *args):
        '''Convert args into a cell tuple'''
        # create a closure that we can rip its cell list from
        newinstruction = lambda op,i: op + chr(i&0x00ff) + chr((i&0xff00)/0x100)

        LOAD_CONST = '\x64'     # LOAD_CONST /co_consts/
        LOAD_DEREF = '\x88'     # LOAD_DEREF /co_freevars/
        STORE_DEREF = '\x89'    # STORE_DEREF  /co_cellvars/
        LOAD_CLOSURE = '\x87'   # LOAD_CLOSURE /co_cellvars/
        MAKE_CLOSURE = '\x86'   # MAKE_CLOSURE /number/ ???
        STORE_FAST = '\x7d'     # STORE_FAST /co_varnames/
        LOAD_FAST = '\x7c'      # LOAD_FAST /co_varnames/
        BUILD_TUPLE = '\x66'    # BUILD_TUPLE /length/
        POP_TOP = '\x01'
        RETURN_VALUE = '\x53'

        # generate inner code object
        result = []
        for i in range(len(args)):
            result.append(newinstruction(LOAD_DEREF, i))
            result.append(POP_TOP)
        result.append(newinstruction(LOAD_CONST, 0))
        result.append(RETURN_VALUE)

        freevars = __builtins__['tuple']( chr(x+65) for x in range(len(args)) )
        innercodeobj = code.new(0, 0, 0, 0, ''.join(result), (None,), (), (), '', '<closure>', 0, '', freevars, ())
    
        # generate outer code object for >= 2.5
        result = []
        for i in range(len(args)):
            result.append( newinstruction(LOAD_CONST, i+1) )
            result.append( newinstruction(STORE_DEREF, i) )
            result.append( newinstruction(LOAD_CLOSURE, i) )

        result.append( newinstruction(BUILD_TUPLE, len(args)) )
        result.append( newinstruction(LOAD_CONST, 0) )
        result.append( newinstruction(MAKE_CLOSURE, 0) )    # XXX: different for <= 2.4
        result.append( RETURN_VALUE )

        outercodestring = ''.join(result)

        # build constants list
        result = list.get()(args)
        result.insert(0, innercodeobj)
        constants = __builtins__['tuple'](result)

        # names within outer code object
        cellvars = __builtins__['tuple']( chr(x+65) for x in range(len(args)) )
        outercodeobj = code.new(0, 0, 0, 0, outercodestring, constants, (), (), '', '<function>', 0, '', (), cellvars)

        # finally fucking got it
        fn = function.new(outercodeobj, {})
        return fn().func_closure

@lookup.define
class generator(special):
    attributes = [
        'gi_code', 'gi_frame', 'gi_running'
    ]

    @classmethod
    def get(cls):
        return (x for x in []).__class__

    @classmethod
    def deserialize_dict(cls, object, **kwds):
        raise NotImplementedError('Not possible yet to instantiate a generator object')

        # XXX: we "could" get obnoxious and bypass the readonly attribute requirement
        #      in order to copy a code object to an already existing generator.

        result = (object[k] for k in cls.attributes)
        result = __builtins__['tuple'](result)
        return cls.new(*result)

    @classmethod
    def new(cls, codeobj, frame, running):
        return cls.get()(codeobj, frame, running)

@lookup.define
class frame(special):
    attributes = [
        'f_back', 'f_builtins', 'f_code', 'f_exc_traceback', 'f_exc_type', 'f_exc_value',
        'f_globals', 'f_lasti', 'f_lineno', 'f_locals', 'f_restricted', 'f_trace'
    ]

    @classmethod
    def get(cls):
        return (x for x in []).gi_frame.__class__

    @classmethod
    def deserialize_dict(cls, object, **kwds):
        raise NotImplementedError('Not possible yet to instantiate a frame object')

@lookup.define
class set(container):
    @classmethod
    def get(cls):
        return __builtins__['set']().__class__

    @classmethod
    def serialize(cls, object, **kwds):
        return [ lookup.dumps(x, **kwds) for x in object ]

    @classmethod
    def deserialize(cls, object, **kwds):
        return set.new(lookup.loads(x, **kwds) for x in object)

@lookup.define
class property(special):
    attributes=['fdel','fset','fget']
    @classmethod
    def get(cls):
        return __builtins__['property']().__class__

    @classmethod
    def deserialize_dict(cls, object, **kwds):
        return cls.get()(fget=object['fget'], fset=object['fset'], fdel=object['fdel'])

if __name__ == '__main__':
    import fu; reload(fu)

    data = { 'name' : 'me', 'integer': 1 , 'tuple' : (5,4,3,2, {1:2,3:4})}
    class junk(object):
        property = data
        def test(self):
            return "hi, i'm %x"% id(self)

        def dosomething(self):
            print self.property

    class junk2:
        def test(self):
            return 'ok'
        property = {'name' : 1}


    a = junk
    s = fu.dumps(a)
    b = fu.loads(s)

    _a = a()
    _b = b()

    print a,_a.test(),_a.property
    print b,_b.test(),_b.property
    print a is b

    def test(x):
        def closure():
            print 'hello', x
        return closure

    f = test('computer')

    a = fu.function.dumps(f)
    b = fu.function.loads(a)
    b()

