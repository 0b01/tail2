import Head from "next/head";
import Footer from "../components/footer/Footer";
import ContactForm from "../components/forms/contact-form/contact-form";
import Navbar from "../components/navbar/navbar";
import Hello from "../sections/hello/hello";

const Contact = () => {
    return (
        <>
            <Head>
                <title>Contact | tail2</title>
                <meta name="viewport" content="initial-scale=1.0, width=device-width" />
            </Head>
            <Navbar />
            {/* <ContactForm /> */}
            
            <Hello />
            <Footer />
        </>
    )
}

export default Contact;