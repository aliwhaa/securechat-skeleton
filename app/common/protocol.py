# app/common/protocol.py
from pydantic import BaseModel, Field, validator
from typing import Optional
import base64


class Hello(BaseModel):
    type: str = Field("hello", const=True)
    cert: str  # PEM as text
    nonce: str  # base64-encoded nonce

class ServerHello(BaseModel):
    type: str = Field("server hello", const=True)
    cert: str
    nonce: str


class Register(BaseModel):
    type: str = Field("register", const=True)
    email: str
    username: str
    # password field should be already hashed and base64-encoded by client under ephemeral AES
    pwd: str
    salt: Optional[str] = None  # base64 encoded salt (server will set when responding if needed)


class Login(BaseModel):
    type: str = Field("login", const=True)
    email: str
    # pwd is base64(sha256(salt||pwd)) as specified -> treated as opaque string here
    pwd: str
    nonce: Optional[str] = None


class DHClient(BaseModel):
    type: str = Field("dh client", const=True)
    g: int
    p: int
    A: int


class DHServer(BaseModel):
    type: str = Field("dh server", const=True)
    B: int


class Msg(BaseModel):
    type: str = Field("msg", const=True)
    seqno: int
    ts: int  # unix ms
    ct: str  # base64 ciphertext
    sig: str  # base64 signature

    @validator("seqno")
    def seq_must_be_positive(cls, v):
        if v < 1:
            raise ValueError("seqno must be >= 1")
        return v


class Receipt(BaseModel):
    type: str = Field("receipt", const=True)
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64 signature over transcript hash


class Error(BaseModel):
    type: str = Field("error", const=True)
    code: str
    message: Optional[str] = None

