import FaqSection from "../sections/faq-section/faq-section";
import Footer from "../components/footer/Footer";
import Navbar from "../components/navbar/navbar";
import Head from "next/head";

const Faq = () => {
    return (
        <>
            <Head>
                <title>Faq | tail2</title>
                <meta name="viewport" content="initial-scale=1.0, width=device-width" />
            </Head>
            <Navbar />
            <FaqSection />
            <Footer />
        </>
    )
}

export default Faq;