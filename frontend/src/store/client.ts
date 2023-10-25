import { GatewayClient } from "../../generated/gateway_pb_service";

export const client = new GatewayClient("http://localhost:8080");
