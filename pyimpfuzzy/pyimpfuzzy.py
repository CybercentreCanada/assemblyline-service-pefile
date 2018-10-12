#!/usr/bin/env python

import pefile
import ssdeep
import ordlookup


def hash_compare(hash1, hash2):
    return ssdeep.compare(hash1, hash2)


class pefileEx(pefile.PE):

    def __init__(self, *args, **kwargs):
        pefile.PE.__init__(self, *args, **kwargs)

    def calc_impfuzzy(self, sort=False, return_list=False):
        impstrs = []
        exts = ["ocx", "sys", "dll"]
        if not hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            return ""
        for entry in self.DIRECTORY_ENTRY_IMPORT:
            no_iat_flag = False
            if isinstance(entry.dll, bytes):
                libname = entry.dll.decode().lower()
            else:
                libname = entry.dll.lower()
            parts = libname.rsplit(".", 1)
            if len(parts) > 1 and parts[1] in exts:
                libname = parts[0]

            if not entry.imports[0].struct_iat:
                no_iat_flag = True

            for imp in entry.imports:
                funcname = None
                if imp.struct_iat or no_iat_flag:
                    if not imp.name:
                        funcname = ordlookup.ordLookup(
                            entry.dll.lower(), imp.ordinal, make_name=True)
                        if not funcname:
                            raise Exception("Unable to look up ordinal %s:%04x" % (
                                entry.dll, imp.ordinal))
                    else:
                        funcname = imp.name

                if not funcname:
                    continue

                if isinstance(funcname, bytes):
                    funcname = funcname.decode()
                impstrs.append("%s.%s" % (libname.lower(), funcname.lower()))

        if sort:
            impstrs.sort()

        if return_list:
            return impstrs
        else:
            apilist = ",".join(impstrs)
            return apilist

    def get_impfuzzy(self, sort=False):
        # pe = pefileEx(file)
        apilist = self.calc_impfuzzy(sort)

        return ssdeep.hash(apilist)

    # def get_impfuzzy_data(self, file, sort=False):
    #     pe = pefileEx(data=file)
    #     apilist = pe.calc_impfuzzy(sort)
    #
    #     return ssdeep.hash(apilist)