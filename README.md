# CRUDup

CRUDup is an opinionated boilerplate for making scalable CRUD apps. It provides the entire stack for a simple system which lets users register, login and logout. That's all it does, but you can follow the same general patterns to build bigger stuff.

From back to front, technology decisions are as follows:

- **Database**: [YugabyteDB](https://www.yugabyte.com/) lets us scale horizontally with ease while providing a familiar Postgres-style interface that we'll query using [SQLx](https://github.com/launchbadge/sqlx).
- **Backend**: [Tonic](https://github.com/hyperium/tonic) lets us define interfaces using [Protocol Buffers](https://protobuf.dev/) and easily communicate between services via [gRPC](https://grpc.io/).
- **Frontend**: [TypeScript](https://www.typescriptlang.org/) & [React](https://react.dev/) with [RTK](https://redux-toolkit.js.org/) and [Tailwind](https://tailwindcss.com/) let us crank out pretty UI fast. We'll use [gRPC-Web](https://github.com/grpc/grpc-web) to make the backend/frontend interface feel just like any other service boundary.

Other tools include [Mcrouter](https://github.com/facebook/mcrouter) for caching, and of course [Docker](https://www.docker.com/) and [Kubernetes](https://kubernetes.io/) for containerization and orchestration.

The system is fully typed across the stack, so we can move fast & break things wherever we want, then let the machine tell us how to get them working again.

## Setup

First you'll need a kubernetes cluster. I usually use [kind](https://kind.sigs.k8s.io/) for local dev.

### Database

Setup yugabyte DB ([more info here](https://docs.yugabyte.com/preview/quick-start/)) on your cluster using the following command:

```
helm install yugabyte yugabytedb/yugabyte \
--version 2.19.3 \
--set resource.master.requests.cpu=0.5,resource.master.requests.memory=0.5Gi,\
resource.tserver.requests.cpu=0.5,resource.tserver.requests.memory=0.5Gi,\
enableLoadBalancer=True --namespace app
```

Forward port 5433 from the DB service: `kubectl port-forward -n app service/yb-tserver-service 5432:5433`

Then run the migrations: `sqlx migrate run`

### Cache

Next apply the Mcrouter operator to your cluster using the following command from the project root: `kubectl apply -f _kubernetes/operators/mcrouter.yaml`. This is used to manage a memcached cluster used by the auth service. The cache cluster is horizontally scalable, and you can extend this pattern for other Read operations in your CRUD app. 

### Backend Services

Build the backend services by running `docker compose build` from the project root. This will create images for the `gateway` and `auth` services. Once the images are built, load them into your cluster and run `kubectl apply -k _kubernetes` to spin up the default configuration (2 instances of each service).

#### Load Balancing

The deployments are configured to use gRPC load balancing provided by a [linkerd](https://linkerd.io/) sidecar. You will need to [setup linkerd](https://linkerd.io/2.14/getting-started/) on your cluster to get load balancing across the gRPC service instances.

### Frontend

Once all backend components are running, expose port 50051 from the gateway service using `kubectl port-forward -n app service/gateway 50051:50051` (if running locally), or your preferred form of ingress. From the `frontend` directory, use `npm run dev` then visit `localhost:8080` in your browser.

If everything is setup correctly, you should be able to register, login, logout, etc from the client. Congratulations, you're now the proud owner of an app which scales flexibly to millions of users!

## Contributing

I made this quickly to use as a starting point for another project I'm working on, and it's likely I missed something. If you notice any issues, PRs are welcome!
