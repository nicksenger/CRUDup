// package: gateway
// file: gateway.proto

import * as jspb from "google-protobuf";
import * as google_protobuf_empty_pb from "google-protobuf/google/protobuf/empty_pb";

export class RegisterRequest extends jspb.Message {
  getUsername(): string;
  setUsername(value: string): void;

  getPassword(): string;
  setPassword(value: string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RegisterRequest.AsObject;
  static toObject(includeInstance: boolean, msg: RegisterRequest): RegisterRequest.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: RegisterRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RegisterRequest;
  static deserializeBinaryFromReader(message: RegisterRequest, reader: jspb.BinaryReader): RegisterRequest;
}

export namespace RegisterRequest {
  export type AsObject = {
    username: string,
    password: string,
  }
}

export class RegisterResponse extends jspb.Message {
  getUserId(): Uint8Array | string;
  getUserId_asU8(): Uint8Array;
  getUserId_asB64(): string;
  setUserId(value: Uint8Array | string): void;

  getSessionToken(): Uint8Array | string;
  getSessionToken_asU8(): Uint8Array;
  getSessionToken_asB64(): string;
  setSessionToken(value: Uint8Array | string): void;

  getRefreshToken(): Uint8Array | string;
  getRefreshToken_asU8(): Uint8Array;
  getRefreshToken_asB64(): string;
  setRefreshToken(value: Uint8Array | string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RegisterResponse.AsObject;
  static toObject(includeInstance: boolean, msg: RegisterResponse): RegisterResponse.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: RegisterResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RegisterResponse;
  static deserializeBinaryFromReader(message: RegisterResponse, reader: jspb.BinaryReader): RegisterResponse;
}

export namespace RegisterResponse {
  export type AsObject = {
    userId: Uint8Array | string,
    sessionToken: Uint8Array | string,
    refreshToken: Uint8Array | string,
  }
}

export class LoginRequest extends jspb.Message {
  getUsername(): string;
  setUsername(value: string): void;

  getPassword(): string;
  setPassword(value: string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): LoginRequest.AsObject;
  static toObject(includeInstance: boolean, msg: LoginRequest): LoginRequest.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: LoginRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): LoginRequest;
  static deserializeBinaryFromReader(message: LoginRequest, reader: jspb.BinaryReader): LoginRequest;
}

export namespace LoginRequest {
  export type AsObject = {
    username: string,
    password: string,
  }
}

export class LoginResponse extends jspb.Message {
  getUserId(): Uint8Array | string;
  getUserId_asU8(): Uint8Array;
  getUserId_asB64(): string;
  setUserId(value: Uint8Array | string): void;

  getSessionToken(): Uint8Array | string;
  getSessionToken_asU8(): Uint8Array;
  getSessionToken_asB64(): string;
  setSessionToken(value: Uint8Array | string): void;

  getRefreshToken(): Uint8Array | string;
  getRefreshToken_asU8(): Uint8Array;
  getRefreshToken_asB64(): string;
  setRefreshToken(value: Uint8Array | string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): LoginResponse.AsObject;
  static toObject(includeInstance: boolean, msg: LoginResponse): LoginResponse.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: LoginResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): LoginResponse;
  static deserializeBinaryFromReader(message: LoginResponse, reader: jspb.BinaryReader): LoginResponse;
}

export namespace LoginResponse {
  export type AsObject = {
    userId: Uint8Array | string,
    sessionToken: Uint8Array | string,
    refreshToken: Uint8Array | string,
  }
}

export class RefreshRequest extends jspb.Message {
  getUserId(): Uint8Array | string;
  getUserId_asU8(): Uint8Array;
  getUserId_asB64(): string;
  setUserId(value: Uint8Array | string): void;

  getRefreshToken(): Uint8Array | string;
  getRefreshToken_asU8(): Uint8Array;
  getRefreshToken_asB64(): string;
  setRefreshToken(value: Uint8Array | string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RefreshRequest.AsObject;
  static toObject(includeInstance: boolean, msg: RefreshRequest): RefreshRequest.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: RefreshRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RefreshRequest;
  static deserializeBinaryFromReader(message: RefreshRequest, reader: jspb.BinaryReader): RefreshRequest;
}

export namespace RefreshRequest {
  export type AsObject = {
    userId: Uint8Array | string,
    refreshToken: Uint8Array | string,
  }
}

export class RefreshResponse extends jspb.Message {
  getSessionToken(): Uint8Array | string;
  getSessionToken_asU8(): Uint8Array;
  getSessionToken_asB64(): string;
  setSessionToken(value: Uint8Array | string): void;

  getRefreshToken(): Uint8Array | string;
  getRefreshToken_asU8(): Uint8Array;
  getRefreshToken_asB64(): string;
  setRefreshToken(value: Uint8Array | string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RefreshResponse.AsObject;
  static toObject(includeInstance: boolean, msg: RefreshResponse): RefreshResponse.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: RefreshResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RefreshResponse;
  static deserializeBinaryFromReader(message: RefreshResponse, reader: jspb.BinaryReader): RefreshResponse;
}

export namespace RefreshResponse {
  export type AsObject = {
    sessionToken: Uint8Array | string,
    refreshToken: Uint8Array | string,
  }
}

export class LogoutRequest extends jspb.Message {
  getUserId(): Uint8Array | string;
  getUserId_asU8(): Uint8Array;
  getUserId_asB64(): string;
  setUserId(value: Uint8Array | string): void;

  getSessionToken(): Uint8Array | string;
  getSessionToken_asU8(): Uint8Array;
  getSessionToken_asB64(): string;
  setSessionToken(value: Uint8Array | string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): LogoutRequest.AsObject;
  static toObject(includeInstance: boolean, msg: LogoutRequest): LogoutRequest.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: LogoutRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): LogoutRequest;
  static deserializeBinaryFromReader(message: LogoutRequest, reader: jspb.BinaryReader): LogoutRequest;
}

export namespace LogoutRequest {
  export type AsObject = {
    userId: Uint8Array | string,
    sessionToken: Uint8Array | string,
  }
}

