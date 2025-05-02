import subprocess

from . import base


class ViewProtobuf(base.View):
    """Human friendly view of protocol buffers
    The view uses the protoc compiler to decode the binary
    """

    name = "Protocol Buffer"
    prompt = ("protobuf", "p")
    content_types = [
        "application/x-protobuf",
        "application/x-protobuffer",
        "application/x-google-protobuf",
        "application/x-google-protobuffer",
    ]

    def is_available(self):
        try:
            p = subprocess.Popen(
                ["goprotoc", "--version"],
                stdout=subprocess.PIPE
            )
            out, _ = p.communicate()
            return out.startswith(b"libprotoc")
        except:
            return False

    def __call__(self, data, **metadata):
        # if not self.is_available():
        #     raise NotImplementedError("goprotoc not found. Please make sure 'goprotoc' is available in $PATH.")

        # if Popen raises OSError, it will be caught in
        # get_content_view and fall back to Raw
        p = subprocess.Popen(['goprotoc', '--decode_raw'],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        decoded, _ = p.communicate(input=data)
        if not decoded:
            raise ValueError("Failed to parse input.")
        return "Protobuf", base.format_text(decoded)
