#define PY_SSIZE_T_CLEAN
#include <Python.h>

int main() 
{
    Py_Initialize();
    PyObject* registerutils = PyImport_ImportModule("cloudregister.registerutils");
    PyObject* registryauth = PyObject_GetAttrString(registerutils, (char*)"get_activations");
    PyObject* authresult = PyObject_CallObject(registryauth, NULL);
    Py_ssize_t success = PyDict_Size(authresult);
    Py_XDECREF(registerutils);
    PyErr_Clear();
    Py_Finalize();
    // get_activations returns an empty dict on failure
    if (success == 0) {
        fprintf(stderr, "Registry re-authentication failed. Please consult '/var/log/cloudregister' for details\n");
        exit(1);
    }
    printf("Registry re-authentication success\n");
    return 0;
}
