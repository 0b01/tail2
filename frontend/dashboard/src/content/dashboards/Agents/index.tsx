import { Helmet } from 'react-helmet-async';
import PageHeader from './PageHeader';
import PageTitleWrapper from 'src/components/PageTitleWrapper';
import { Card, CardContent, Container, Grid, Typography } from '@mui/material';
import Footer from 'src/components/Footer';

import AccountBalance from './AccountBalance';
import Wallets from './Wallets';
import AgentCard from './AgentCard';
import WatchList from './WatchList';
import { useEffect, useState } from 'react';
import { IAgents, IDBs } from './types';
import DbCard from './DbCard';

function AgentGrid(agents: IAgents) {
  let cards = Object.entries(agents).map(([k, v]) => <AgentCard host_name={k} agent={v} key={k}/>);
  return (
    <>
      <Grid item lg={12} xs={12}>
        <Grid container direction={"row"} justifyItems={"flex-start"} alignItems={"flex-start"} spacing={2}>
          {cards}
        </Grid>
      </Grid>
    </>
  );
}

function DbGrid(dbs: IDBs) {
  let cards = Object.entries(dbs).map(([k, v]) => <DbCard key={k} db={v}/>);
  return (
    <>
      <Grid item lg={12} xs={12}>
        <Grid container direction={"row"} justifyItems={"flex-start"} alignItems={"flex-start"} spacing={2}>
          {cards}
        </Grid>
      </Grid>
    </>
  );
}


function Agents() {
  const [agents, setAgents] = useState<IAgents>({});
  const [dbs, setDBs] = useState<IDBs>({});
  useEffect(() => {
    async function refreshAgents() {
      let agents = await fetch("/api/agents");
      setAgents(await agents.json());

      let db = await fetch("/api/dbs");
      setDBs(await db.json());
    }

    let events = new EventSource("/api/agent/events");
    events.onmessage = () => refreshAgents();

    refreshAgents();
  }, []);

  return (
    <>
      <Helmet>
        <title>Agents - tail2</title>
      </Helmet>

      <PageTitleWrapper>
        <Grid container alignItems="center">
          <Grid item>
          </Grid>
          <Grid item>
            <Typography variant="h3" component="h3" gutterBottom>
              Agents
            </Typography>
            <Typography variant="subtitle2">
              View connected agents
            </Typography>
          </Grid>
        </Grid>
      </PageTitleWrapper>
      <Container maxWidth="lg">
        <Grid container direction="row" justifyContent="center" alignItems="stretch" spacing={4}>
          <AgentGrid {...agents} />
        </Grid>
      </Container>

      <PageTitleWrapper>
        <Grid container alignItems="center">
          <Grid item>
          </Grid>
          <Grid item>
            <Typography variant="h3" component="h3" gutterBottom>
              History
            </Typography>
            <Typography variant="subtitle2">
              View collected stack traces
            </Typography>
          </Grid>
        </Grid>
      </PageTitleWrapper>

      <Container maxWidth="lg">
        <Grid container direction="row" justifyContent="center" alignItems="stretch" spacing={4}>
          <DbGrid {...dbs} />
        </Grid>
      </Container>

      <Footer />
    </>
  );
}

export default Agents;
