import java.io.*;
import java.util.*;

class TSTNode {
    char data;
    boolean isEnd;
    int phishing_occurence;
    int legitimate_occurence;
    float weight;
    TSTNode left, middle, right;
    public TSTNode(char data) {
        this.data = data;
        this.isEnd = false;
        this.left = null;
        this.middle = null;
        this.right = null;
    }
}
class TernarySearchTree {
    public static TSTNode root;
    public static ArrayList<String> al;
    public TernarySearchTree() {
        root = null;
    }
    public void weightCalculation(TSTNode root) {  //This function is used to calculate the weights of the ngrams.
        if (root.phishing_occurence > 0 && root.legitimate_occurence == 0) {
            root.weight = 1; // a very unique n-gram for phishing medium
        } else if (root.phishing_occurence == 0 && root.legitimate_occurence > 0) {
            root.weight = -1; // a very unique n-gram for legitimate medium
        } else if (root.phishing_occurence > 0 && root.legitimate_occurence > 0) {
            if (root.phishing_occurence > root.legitimate_occurence) {
                root.weight = (float) Math.min(root.phishing_occurence, root.legitimate_occurence) / Math.max(root.phishing_occurence, root.legitimate_occurence); // (0,1)
            } else if (root.phishing_occurence < root.legitimate_occurence) {
                root.weight = (float) -Math.min(root.phishing_occurence, root.legitimate_occurence) / Math.max(root.phishing_occurence, root.legitimate_occurence); //(-1,0)
            } else {
                root.weight = 0; // n-gram appears equally in both of the mediums.
            }
        }
    }
    public void insert(String word, String type) {
        root = insert(root, word.toCharArray(), 0, type);
    }
    public TSTNode insert(TSTNode r, char[] word, int ptr, String type) { //This function is used to insert the ngrams to the ternary search tree.
        if (r == null)
            r = new TSTNode(word[ptr]);
        if (word[ptr] < r.data)
            r.left = insert(r.left, word, ptr, type);
        else if (word[ptr] > r.data)
            r.right = insert(r.right, word, ptr, type);
        else {
            if (ptr + 1 < word.length)
                r.middle = insert(r.middle, word, ptr + 1, type);
            else {
                r.isEnd = true;
                if (type.equals("p")) {
                    r.phishing_occurence++;
                }
                if (type.equals("l")) {
                    r.legitimate_occurence++;
                }
            }
        }
        return r;
    }
    public void delete(String word) {
        delete(root, word.toCharArray(), 0);
    }
    private void delete(TSTNode r, char[] word, int ptr) { // This function is used to delete the insignificant ngrams. And finding the deleted ngram count.
        if (r == null)
            return;
        if (word[ptr] < r.data)
            delete(r.left, word, ptr);
        else if (word[ptr] > r.data)
            delete(r.right, word, ptr);
        else {
            if (r.isEnd && ptr == word.length - 1) {
                r.isEnd = false;
                TST.deleted_ngram++;
            } else if (ptr + 1 < word.length)
                delete(r.middle, word, ptr + 1);
        }
    }
    public void traverse(TSTNode r, String str) { //This function is the most important function in this program, it is used for traversing through the ternary search tree and filling the arraylists and linkedhashmaps.
        if (r != null) {
            traverse(r.left, str);
            str = str + r.data;
            if (r.isEnd) { // If the given ngram is found:
                weightCalculation(r);
                if (r.phishing_occurence > 0 && r.legitimate_occurence > 0) {  //In this if scope this part adds the given ngrams name and values for the main LinkedHashMaps.
                    TST.allWeights.put(str, r.weight);
                    TST.phishingFrequencies.put(str, r.phishing_occurence);
                    TST.legitimateFrequencies.put(str, r.legitimate_occurence);
                } else if (r.phishing_occurence > 0 && r.legitimate_occurence == 0) {//In this if scope this part adds the given ngrams to all weights and phishing frequencies linkedHashMaps.
                    TST.allWeights.put(str, r.weight);
                    TST.phishingFrequencies.put(str, r.phishing_occurence);
                } else if (r.phishing_occurence == 0 && r.legitimate_occurence > 0) {//In this if scope this part adds the given ngrams to all weights and legitimate frequencies linkedHashMaps.
                    TST.allWeights.put(str, r.weight);
                    TST.legitimateFrequencies.put(str, r.legitimate_occurence);
                }
            }
            traverse(r.middle, str);
            str = str.substring(0, str.length() - 1);
            traverse(r.right, str);
        }
    }
}
public class TST {
    public static LinkedHashMap<String, Float> allWeights = new LinkedHashMap<>(); //LinkedHashMap for weights text.
    public static LinkedHashMap<String, Integer> phishingFrequencies = new LinkedHashMap<>(); //LinkedHashMap for strong phishing features.txt
    public static LinkedHashMap<String, Integer> legitimateFrequencies = new LinkedHashMap<>(); //LinkedHashMap for strong legitimate features.txt
    public static ArrayList<String> p5000 = new ArrayList<>(); // This is the array list used for printing the significant ngrams.
    public static ArrayList<String> l5000 = new ArrayList<>(); // This is the array list used for printing the significant ngrams.
    public static int deleted_ngram = 0;
    public static int legit_test_lineCounter = 0;
    public static int phishing_test_lineCounter = 0;
    public static int weightFileLineCounter = 0;
    public static int legit_train_line_counter = 0;
    public static int phishing_train_line_counter = 0;
    public static final int ngram = 4; // NGRAM variable that can be changed.
    public static final int feature_size = 5000; // FEATURE_SIZE variable that can be changed.

    public static void printingConsoleOutput(int featureSize, float accuracy, int lTestCounter, int pTestCounter, int lTrainCounter, int pTrainCounter, int weightLineCounter, int TP, int TN, int FP, int FN, int UP, int UL) {
        /*This function is used for printing the console output. */
        System.out.println("n-gram based phishing detection via TST");
        System.out.println();
        System.out.println("Legitimate training file has been loaded with [" + lTrainCounter + "] instances");
        System.out.println("Legitimate test file has been loaded with [" + lTestCounter + "] instances");
        System.out.println("Phishing training file has been loaded with [" + pTrainCounter + "] instances");
        System.out.println("Phishing test file has been loaded with [" + pTestCounter + "] instances");
        System.out.println("TST has been loaded with [" + lTestCounter + "] ngrams");
        System.out.println("TST has been loaded with [" + pTestCounter + "] ngrams");
        System.out.println(featureSize + " strong phishing n-grams have been saved to the file strong_phishing_features.txt");
        System.out.println(featureSize + " strong legitimate n-grams have been saved to the file strong_legitimate_features.txt");
        System.out.println(weightLineCounter + " n-grams + weights have been saved to the file  all_feature_weights.txt");
        System.out.println(deleted_ngram + " insignificant n-grams have been removed from the TST");
        System.out.println("TP:" + TP + " FN:" + FN + " TN:" + TN + " FP:" + FP + " Unpredictable Phishing:" + UP + " Unpredictable Legitimate:" + UL + "");
        System.out.println("Accuracy: " + accuracy);
    }
    public static float accuracyCalculator(int TP, int TN, int FP, int FN, int UP, int UL) { // This function is used to calculate the accuracy.
        float accuracy = 0;
        accuracy = (float) (TP + TN) / (TP + TN + FP + FN + UP + UL);
        return accuracy;
    }
    public static void printingWeights(LinkedHashMap<String, Float> hshmap, FileWriter output) throws IOException {  //This function is used to print the allweights LinkedHashMap and calculating the line count.
        output.write("All N-Gram Weights\n");
        int i = 0;
        for (Map.Entry m : hshmap.entrySet()) {
            output.write(m.getKey() + " - weight: " + m.getValue() + "\n");
            i++;
        }
        weightFileLineCounter = i;
    }
    public static void printingLegitimateFrequencies(LinkedHashMap<String, Integer> hshmap, FileWriter output, int feature_size) throws IOException { //This function is used to print the strong legitimate features.
        int i = 1;
        output.write("Most important legitimate n_grams\n");
        for (Map.Entry m : hshmap.entrySet()) {
            output.write(i + ". " + m.getKey() + " - freq: " + m.getValue() + "\n");
            p5000.add((String) m.getKey());
            i++;
            if (i == feature_size + 1) {
                break;
            }
        }
    }
    public static void printingPhishingFrequencies(LinkedHashMap<String, Integer> hshmap, FileWriter output, int feature_size) throws IOException {//This function is used to print the strong phishing features.
        int i = 1;
        output.write("Most important phishing n_grams\n");
        for (Map.Entry m : hshmap.entrySet()) {
            output.write(i + ". " + m.getKey() + " - freq: " + m.getValue() + "\n");
            l5000.add((String) m.getKey());
            i++;
            if (i == feature_size + 1) {
                break;
            }
        }
    }
    private static LinkedHashMap<String, Float> sortByFloatValue(LinkedHashMap<String, Float> unsortMap) { //This function is used to sort the AllWeights LinkedHashMap according to the given order.
        List<Map.Entry<String, Float>> list = new LinkedList<>(unsortMap.entrySet());
        list.sort(Map.Entry.comparingByValue());
        Collections.reverse(list);
        /// Loop the sorted list and put it into a new insertion order Map
        LinkedHashMap<String, Float> sortedMap = new LinkedHashMap<>();
        for (Map.Entry<String, Float> entry : list) {
            sortedMap.put(entry.getKey(), entry.getValue());
        }
        return sortedMap;
    }
    public static LinkedHashMap<String, Integer> sortInDescendingOrder(LinkedHashMap<String, Integer> map) { // This function is used for sorting the frequency linkedHashMaps in the given order.
        LinkedHashMap<String, Integer> reverseSortedMap = new LinkedHashMap<>();
        map.entrySet().stream().sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                .forEachOrdered(x -> reverseSortedMap.put(x.getKey(), x.getValue()));
        return reverseSortedMap;
    }
    public static void mainFunction() throws IOException {
        FileWriter strongPhishing = (new FileWriter("strong_phishing_features.txt")); //Strong phishing text
        FileWriter strongLegitimate = (new FileWriter("strong_legitimate_features.txt")); //Strong legitimate text
        FileWriter all_weights_output = (new FileWriter("all_feature_weights.txt")); // All feature weights text
        float accuracy = 0;
        int true_positive = 0;
        int false_positive = 0;
        int true_negative = 0;
        int false_negative = 0;
        int unpredictable_phishing = 0;
        int unpredictable_legitimate = 0;

        TernarySearchTree tst = new TernarySearchTree();
        BufferedReader phishingtrain = new BufferedReader(new FileReader(new File("phishing-train.txt"))); // phishing train file reading part
        String phishing_train_line;
        while ((phishing_train_line = phishingtrain.readLine()) != null) {
            phishing_train_line = phishing_train_line.replaceAll("https", "");//This is the part that is removing the unnecessary words.
            phishing_train_line = phishing_train_line.replaceAll("http", "");
            phishing_train_line = phishing_train_line.replaceAll("www", "");
            phishing_train_line = phishing_train_line.toLowerCase();
            for (int i = 0; i < phishing_train_line.length() - ngram + 1; i++) {
                tst.insert(phishing_train_line.substring(i, i + ngram), "p");
            }
            phishing_train_line_counter++;
        }
        BufferedReader legitimatetrain = new BufferedReader(new FileReader(new File("legitimate-train.txt"))); //legitimate train file reading part
        String legit_train_line;
        while ((legit_train_line = legitimatetrain.readLine()) != null) {
            legit_train_line = legit_train_line.replaceAll("https", "");//This is the part that is removing the unnecessary words.
            legit_train_line = legit_train_line.replaceAll("http", "");
            legit_train_line = legit_train_line.replaceAll("www", "");
            legit_train_line = legit_train_line.toLowerCase();
            for (int i = 0; i < legit_train_line.length() - ngram + 1; i++) {
                tst.insert(legit_train_line.substring(i, i + ngram), "l");
            }
            legit_train_line_counter++;
        }
        tst.traverse(TernarySearchTree.root, "");

        phishingFrequencies = sortInDescendingOrder(phishingFrequencies);
        legitimateFrequencies = sortInDescendingOrder(legitimateFrequencies);
        allWeights = sortByFloatValue(allWeights);

        BufferedReader phishingtest = new BufferedReader((new FileReader((new File("phishing-test.txt"))))); // phishing test file reading part
        String phishing_test_line;
        while ((phishing_test_line = phishingtest.readLine()) != null) {
            float weightCounter = 0;
            phishing_test_line = phishing_test_line.replaceAll("https", "");//This is the part that is removing the unnecessary words.
            phishing_test_line = phishing_test_line.replaceAll("http", "");
            phishing_test_line = phishing_test_line.replaceAll("www", "");
            phishing_test_line = phishing_test_line.toLowerCase();
            for (int i = 0; i < phishing_test_line.length() - ngram + 1; i++) {//In this for loop it calculates the weight counters of the test files.
                String ngramWord = phishing_test_line.substring(i, i + ngram);
                if (allWeights.containsKey(ngramWord)) {
                    weightCounter += allWeights.get(ngramWord);
                }
            }
            if (weightCounter > 0) {
                true_positive++;
            } else if (weightCounter < 0) {
                false_positive++;
            } else {
                unpredictable_phishing++;
            }
            phishing_test_lineCounter++;
        }
        BufferedReader legitimatetest = new BufferedReader(new FileReader(new File("legitimate-test.txt"))); // legitimate test file reading part
        String legit_test_line;
        while ((legit_test_line = legitimatetest.readLine()) != null) {
            float weightCounter = 0;
            legit_test_line = legit_test_line.replaceAll("https", "");//This is the part that is removing the unnecessary words.
            legit_test_line = legit_test_line.replaceAll("http", "");
            legit_test_line = legit_test_line.replaceAll("www", "");
            legit_test_line = legit_test_line.toLowerCase();
            for (int i = 0; i < legit_test_line.length() - ngram + 1; i++) {//In this for loop it calculates the weight counters of the test files.
                String ngramWord = legit_test_line.substring(i, i + ngram);
                if (allWeights.containsKey(ngramWord)) {
                    weightCounter += allWeights.get(ngramWord);
                }
            }
            if (weightCounter > 0) {
                false_negative++;
            } else if (weightCounter < 0) {
                true_negative++;
            } else {
                unpredictable_legitimate++;
            }
            legit_test_lineCounter++;
        }
        accuracy = accuracyCalculator(true_positive, true_negative, false_positive, false_negative, unpredictable_phishing, unpredictable_legitimate);
        printingLegitimateFrequencies(legitimateFrequencies, strongLegitimate, feature_size);
        printingPhishingFrequencies(phishingFrequencies, strongPhishing, feature_size);
        printingWeights(allWeights, all_weights_output);

        int j = 0;
        for (Map.Entry m : legitimateFrequencies.entrySet()) { // In this for loop it removes the unsignificant ngrams from the ternary search tree.
            if (j > feature_size) {
                if (!p5000.contains(m.getKey())) {
                    tst.delete((String) m.getKey());
                }
            }
            j++;
        }
        int i = 0;
        for (Map.Entry m : phishingFrequencies.entrySet()) { // In this for loop it removes the unsignificant ngrams from the ternary search tree.
            if (i > feature_size) {
                if (!l5000.contains(m.getKey())) {
                    tst.delete((String) m.getKey());
                }
            }
            i++;
        }
        printingConsoleOutput(feature_size, accuracy, legit_test_lineCounter, phishing_test_lineCounter, legit_train_line_counter, phishing_train_line_counter, weightFileLineCounter, true_positive, true_negative, false_positive, false_negative, unpredictable_phishing, unpredictable_legitimate);
        strongPhishing.close();
        strongLegitimate.close();
        all_weights_output.close();
        phishingtrain.close();
        phishingtest.close();
        legitimatetest.close();
        legitimatetrain.close();
    }
}