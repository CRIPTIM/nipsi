class NonInteractiveSetIntersection:
    """Non-interactive Private Set Intersection base class"""
    def setup(self, secpar, client_count):
        raise NotImplementedError

    def encrypt(self, usk, gid, pt_sets):
        raise NotImplementedError

    def eval(self, ct_sets):
        raise NotImplementedError

    def decrypt(self, ct_sets):
        self.eval(ct_sets)
