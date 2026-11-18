import { withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiService,
  type NapiServiceListOptions,
  type NapiServicePage,
} from "./internal/napi.js";

/** The sandbox and port that receive a Service's requests. */
export interface ServiceTarget {
  readonly sandbox: string;
  readonly port: number;
}

/** Whether a Service routes requests, is disabled, or has no target. */
export type ServiceStatus = "enabled" | "disabled" | "detached" | "unknown";

/** One page returned by `Service.list()` or `Service.listWith()`. */
export interface ServicePage {
  services: Service[];
  nextCursor?: string;
}

/** Configures a new Service. Returned by `Service.builder(slug)`. */
export class ServiceBuilder {
  private readonly slug: string;
  private serviceTarget?: ServiceTarget;

  /** @internal */
  constructor(slug: string) {
    this.slug = slug;
  }

  /** Set the running sandbox and port that receive requests. */
  target(sandbox: string, port: number): this {
    this.serviceTarget = { sandbox, port };
    return this;
  }

  /**
   * Create the Service without retrying.
   */
  async create(): Promise<Service> {
    if (this.serviceTarget !== undefined) {
      validateTargetPort(this.serviceTarget.port);
    }
    const inner = await withMappedErrors(() =>
      napi.Service.create(this.slug, this.serviceTarget),
    );
    return new Service(inner);
  }
}

/** Fields to change in one `service.update()` call. */
export interface ServiceUpdateOptions {
  /** The running sandbox and port that receive requests. */
  readonly target: ServiceTarget;
}

/** Options for one paginated `Service.listWith()` request. */
export class ServiceListBuilder {
  private readonly options: NapiServiceListOptions = {};

  /** Only list Services whose target is the sandbox with this name. */
  sandbox(name: string): this {
    this.options.sandbox = name;
    return this;
  }

  /** Maximum number of Services in this page: 1 through 100, default 20. */
  limit(limit: number): this {
    this.options.limit = limit;
    return this;
  }

  /** Continue after an opaque cursor returned by a previous page. */
  cursor(cursor: string): this {
    this.options.cursor = cursor;
    return this;
  }

  /** @internal */
  toNapi(): NapiServiceListOptions {
    return this.options;
  }
}

/**
 * A public URL for one sandbox port.
 * Services require a cloud backend; properties make no request.
 */
export class Service {
  /** @internal */
  readonly inner: NapiService;

  /** @internal */
  constructor(inner: NapiService) {
    this.inner = inner;
  }

  /** Start configuring a Service with this slug. */
  static builder(slug: string): ServiceBuilder {
    return new ServiceBuilder(slug);
  }

  /** Get a Service by slug. */
  static async get(slug: string): Promise<Service> {
    const inner = await withMappedErrors(() => napi.Service.get(slug));
    return new Service(inner);
  }

  /** List the first page of the organization's Services, in slug order. */
  static async list(): Promise<ServicePage> {
    const page = await withMappedErrors(() => napi.Service.list());
    return servicePageFromNapi(page);
  }

  /** List a configured page of the organization's Services. */
  static async listWith(
    configure: (list: ServiceListBuilder) => ServiceListBuilder,
  ): Promise<ServicePage> {
    const options = configure(new ServiceListBuilder()).toNapi();
    validateListLimit(options.limit);
    const page = await withMappedErrors(() => napi.Service.listWith(options));
    return servicePageFromNapi(page);
  }

  /** The Service's globally unique slug. */
  get slug(): string {
    return this.inner.slug;
  }

  /** The Service's public URL as returned by the backend. */
  get url(): string {
    return this.inner.url;
  }

  /**
   * Whether the Service routes requests, is disabled, or has no target, as of the read that
   * returned this value. `refresh()` returns a current copy.
   */
  get status(): ServiceStatus {
    const status = this.inner.status;
    return status === "enabled" || status === "disabled" || status === "detached"
      ? status
      : "unknown";
  }

  /** The sandbox and port that receive requests, or `null` when the Service is detached. */
  get target(): ServiceTarget | null {
    return this.inner.target ?? null;
  }

  /** When the organization created this Service. */
  get createdAt(): Date {
    return new Date(this.inner.createdAt);
  }

  /** When the Service's state last changed, including a detach. */
  get updatedAt(): Date {
    return new Date(this.inner.updatedAt);
  }

  /**
   * Change the target.
   * The SDK does not retry; get and check the Service when `changed` is `"unknown"`.
   */
  async update(options: ServiceUpdateOptions): Promise<Service> {
    validateTargetPort(options.target.port);
    const inner = await withMappedErrors(() => this.inner.update(options));
    return new Service(inner);
  }

  /**
   * Enable the Service without retrying. To enable a detached Service, set a running target
   * instead.
   */
  async enable(): Promise<Service> {
    const inner = await withMappedErrors(() => this.inner.enable());
    return new Service(inner);
  }

  /** Disable the Service without retrying while retaining its target. */
  async disable(): Promise<Service> {
    const inner = await withMappedErrors(() => this.inner.disable());
    return new Service(inner);
  }

  /** Remove the Service and release its slug without retrying. */
  async remove(): Promise<void> {
    await withMappedErrors(() => this.inner.remove());
  }

  /** Get the Service again and return its current state. This object is not changed. */
  async refresh(): Promise<Service> {
    const inner = await withMappedErrors(() => this.inner.refresh());
    return new Service(inner);
  }
}

function validateListLimit(limit: number | undefined): void {
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1 || limit > 100)) {
    throw new RangeError("limit must be an integer from 1 to 100");
  }
}

function validateTargetPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 0xffff) {
    throw new RangeError("port must be an integer from 1 to 65535");
  }
}

function servicePageFromNapi(page: NapiServicePage): ServicePage {
  return {
    services: page.services.map((inner) => new Service(inner)),
    nextCursor: page.nextCursor,
  };
}
