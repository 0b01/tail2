import { Helmet } from 'react-helmet-async';
import PageHeader from './PageHeader';
import PageTitleWrapper from 'src/components/PageTitleWrapper';
import { Card, CardContent, Container, Grid } from '@mui/material';
import Footer from 'src/components/Footer';

import AccountBalance from './AccountBalance';
import Wallets from './Wallets';
import AgentCard from './AgentCard';
import WatchList from './WatchList';
import { useEffect, useState } from 'react';
import { IAgents } from './types';

function Agents() {
  const [agents, setAgents] = useState<IAgents>({});
  useEffect(() => {
    async function refreshAgents() {
      let ret: IAgents = await (await fetch("/api/agents")).json();
      setAgents(ret);
    }

    let events = new EventSource("/api/agent/events");
    events.onmessage = () => refreshAgents();

    refreshAgents();
  }, []);

  let agent_grid;
  if (Object.keys(agents).length === 0) {
    agent_grid = <Card>
      <CardContent>
        No agent
      </CardContent>
    </Card>;
  }
  else {
    let cards = Object.entries(agents).map(([k, v]) => <AgentCard name={k} agent={v} key={k}/>);
    agent_grid = 
      <>
        <Grid item lg={12} xs={12} style={{minHeight: '800px'}}>
          <Grid container direction={"row"} justifyItems={"flex-start"} alignItems={"flex-start"} spacing={4}>
            {cards}
          </Grid>
        </Grid>
      </>;
  }

  return (
    <>
      <Helmet>
        <title>Agents - tail2</title>
      </Helmet>
      <PageTitleWrapper>
        <PageHeader />
      </PageTitleWrapper>
      <Container maxWidth="lg">
        <Grid
          container
          direction="row"
          justifyContent="center"
          alignItems="stretch"
          spacing={4}
        >
          {/* <Grid item xs={12}>
            <AccountBalance />
          </Grid>
          <Grid item lg={8} xs={12}>
            <Wallets />
          </Grid> */}
          {agent_grid}
          {/* <Grid item xs={12}>
            <WatchList />
          </Grid> */}
        </Grid>
      </Container>
      <Footer />
    </>
  );
}

export default Agents;
