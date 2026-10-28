export interface ActionRequest {
  run_id: string;
  request_id: string;
  action_code?: number;
  action_id?: string;
  target_id: string;
  incident_id?: string;
  policy_version?: string;
}

export interface ExecutionReceipt {
  schema_version: string;
  run_id: string;
  sequence: number;
  request_id: string;
  action_id: string;
  action_code: number;
  target_id: string;
  state_before: number;
  state_after: number;
  decision: string;
  result: string;
  policy_version: string;
  previous_receipt_hash: string;
  receipt_hash: string;
  signature: string;
}

export interface ExecutionResponse {
  success: boolean;
  statusCode: number;
  decision: 'ALLOW' | 'DENIED';
  status: 'EXECUTED' | 'DENIED' | 'ERROR';
  receipt: ExecutionReceipt | null;
  reason: string | null;
  outcome: any;
  isDuplicate: boolean;
}

export class VeriRespondClient {
  constructor(options?: { baseUrl?: string; timeout?: number });
  getHealth(): Promise<any>;
  getSpecs(): Promise<any>;
  execute(actionRequest: ActionRequest): Promise<ExecutionResponse>;
  runScenario(scenario?: string, options?: any): Promise<any>;
  verify(receipts: ExecutionReceipt[], proofData: any, publicKeyPem: string): Promise<any>;
}
