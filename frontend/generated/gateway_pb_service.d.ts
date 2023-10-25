// package: gateway
// file: gateway.proto

import * as gateway_pb from "./gateway_pb";
import * as google_protobuf_empty_pb from "google-protobuf/google/protobuf/empty_pb";
import {grpc} from "@improbable-eng/grpc-web";

type GatewayRegister = {
  readonly methodName: string;
  readonly service: typeof Gateway;
  readonly requestStream: false;
  readonly responseStream: false;
  readonly requestType: typeof gateway_pb.RegisterRequest;
  readonly responseType: typeof gateway_pb.RegisterResponse;
};

type GatewayLogin = {
  readonly methodName: string;
  readonly service: typeof Gateway;
  readonly requestStream: false;
  readonly responseStream: false;
  readonly requestType: typeof gateway_pb.LoginRequest;
  readonly responseType: typeof gateway_pb.LoginResponse;
};

type GatewayRefresh = {
  readonly methodName: string;
  readonly service: typeof Gateway;
  readonly requestStream: false;
  readonly responseStream: false;
  readonly requestType: typeof gateway_pb.RefreshRequest;
  readonly responseType: typeof gateway_pb.RefreshResponse;
};

type GatewayLogout = {
  readonly methodName: string;
  readonly service: typeof Gateway;
  readonly requestStream: false;
  readonly responseStream: false;
  readonly requestType: typeof gateway_pb.LogoutRequest;
  readonly responseType: typeof google_protobuf_empty_pb.Empty;
};

export class Gateway {
  static readonly serviceName: string;
  static readonly Register: GatewayRegister;
  static readonly Login: GatewayLogin;
  static readonly Refresh: GatewayRefresh;
  static readonly Logout: GatewayLogout;
}

export type ServiceError = { message: string, code: number; metadata: grpc.Metadata }
export type Status = { details: string, code: number; metadata: grpc.Metadata }

interface UnaryResponse {
  cancel(): void;
}
interface ResponseStream<T> {
  cancel(): void;
  on(type: 'data', handler: (message: T) => void): ResponseStream<T>;
  on(type: 'end', handler: (status?: Status) => void): ResponseStream<T>;
  on(type: 'status', handler: (status: Status) => void): ResponseStream<T>;
}
interface RequestStream<T> {
  write(message: T): RequestStream<T>;
  end(): void;
  cancel(): void;
  on(type: 'end', handler: (status?: Status) => void): RequestStream<T>;
  on(type: 'status', handler: (status: Status) => void): RequestStream<T>;
}
interface BidirectionalStream<ReqT, ResT> {
  write(message: ReqT): BidirectionalStream<ReqT, ResT>;
  end(): void;
  cancel(): void;
  on(type: 'data', handler: (message: ResT) => void): BidirectionalStream<ReqT, ResT>;
  on(type: 'end', handler: (status?: Status) => void): BidirectionalStream<ReqT, ResT>;
  on(type: 'status', handler: (status: Status) => void): BidirectionalStream<ReqT, ResT>;
}

export class GatewayClient {
  readonly serviceHost: string;

  constructor(serviceHost: string, options?: grpc.RpcOptions);
  register(
    requestMessage: gateway_pb.RegisterRequest,
    metadata: grpc.Metadata,
    callback: (error: ServiceError|null, responseMessage: gateway_pb.RegisterResponse|null) => void
  ): UnaryResponse;
  register(
    requestMessage: gateway_pb.RegisterRequest,
    callback: (error: ServiceError|null, responseMessage: gateway_pb.RegisterResponse|null) => void
  ): UnaryResponse;
  login(
    requestMessage: gateway_pb.LoginRequest,
    metadata: grpc.Metadata,
    callback: (error: ServiceError|null, responseMessage: gateway_pb.LoginResponse|null) => void
  ): UnaryResponse;
  login(
    requestMessage: gateway_pb.LoginRequest,
    callback: (error: ServiceError|null, responseMessage: gateway_pb.LoginResponse|null) => void
  ): UnaryResponse;
  refresh(
    requestMessage: gateway_pb.RefreshRequest,
    metadata: grpc.Metadata,
    callback: (error: ServiceError|null, responseMessage: gateway_pb.RefreshResponse|null) => void
  ): UnaryResponse;
  refresh(
    requestMessage: gateway_pb.RefreshRequest,
    callback: (error: ServiceError|null, responseMessage: gateway_pb.RefreshResponse|null) => void
  ): UnaryResponse;
  logout(
    requestMessage: gateway_pb.LogoutRequest,
    metadata: grpc.Metadata,
    callback: (error: ServiceError|null, responseMessage: google_protobuf_empty_pb.Empty|null) => void
  ): UnaryResponse;
  logout(
    requestMessage: gateway_pb.LogoutRequest,
    callback: (error: ServiceError|null, responseMessage: google_protobuf_empty_pb.Empty|null) => void
  ): UnaryResponse;
}

