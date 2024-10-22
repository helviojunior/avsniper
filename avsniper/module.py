
class Module(object):
    name = ''
    description = ''
    module = ''
    qualname = ''
    order = 99999
    _class = ''

    def __init__(self, name, description, module, qualname, order, class_name):
        self.name = name
        self.description = description
        self.module = module
        self.qualname = qualname
        self._class = class_name
        self.order = order
        pass

    def create_instance(self):
        return self._class()


