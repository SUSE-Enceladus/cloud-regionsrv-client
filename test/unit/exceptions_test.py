from cloudregister.exceptions import CloudRegisterPathError


class TestCloudRegister:
    def test_raise_message_representation(self):
        exception = CloudRegisterPathError('some_error')
        message = format(exception)
        assert message == 'some_error'
