import type { NextPage } from "next";

import Header from "../components/header/header";

import Goals from "../sections/goals/goals";
import Features from "../sections/features/features";
import News from "../sections/news/news";
import Trail from "../sections/trail/trail";
import Footer from "../components/footer/Footer";
import Navbar from "../components/navbar/navbar";
import Head from "next/head";
import Hello from "../sections/hello/hello";
import FaqSection from "../sections/faq-section/faq-section";

const Home: NextPage = () => {
  return (
    <>
      <Head>
        <title>tail2 continuous profiler</title>
        <meta name="viewport" content="initial-scale=1.0, width=device-width" />
        <link href="https://fonts.googleapis.com/css2?family=Fira+Sans:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet"/>
      </Head>
      <Navbar />
      <Hello />
      <Header />
      <FaqSection />
      {/* <Goals />
      <Features />
      <News />
      <Trail /> */}
      <Footer />
    </>
  )
}

export default Home;